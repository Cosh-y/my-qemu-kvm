// device.rs - Device driver for /dev/rkvm_x86
//
// Provides ioctl interface for userspace VMM (qemu) to create and manage VMs

use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOR, _IOW},
    prelude::*,
    miscdevice::{MiscDevice, MiscDeviceRegistration},
};
use core::mem;

use crate::vm::RKvmVm;
use crate::vcpu::RKvmVcpu;
use crate::types::GuestRegs;

// ioctl command numbers - must match qemu/src/mini_kvm.rs
const MINIKVM_MAGIC: u8 = 0xAE;
const RKVM_CREATE_VM: u32 = _IO!(MINIKVM_MAGIC, 1);
const RKVM_CREATE_VCPU: u32 = _IO!(MINIKVM_MAGIC, 2);
const RKVM_RUN: u32 = _IOR!(MINIKVM_MAGIC, 3, MiniKvmRunState);
const RKVM_SET_REGS: u32 = _IOW!(MINIKVM_MAGIC, 4, RegsMessage);
const RKVM_GET_REGS: u32 = _IOR!(MINIKVM_MAGIC, 5, RegsMessage);
const RKVM_SET_MEM: u32 = _IOW!(MINIKVM_MAGIC, 6, GuestMemoryMapMessage);

#[repr(C)]
#[derive(Debug, Clone)]
pub struct GuestMemoryMapMessage {
    pub host_virt_addr: VirtAddr,
    pub guest_phys_addr: GuestPhysAddr,
    pub memory_size: MemSize,
}

// Userspace structures - must match qemu/src/mini_kvm.rs
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct RegsMessage {
     /// RAX register
    pub rax: u64,
    /// RBX register
    pub rbx: u64,
    /// RCX register
    pub rcx: u64,
    /// RDX register
    pub rdx: u64,
    /// RSI register
    pub rsi: u64,
    /// RDI register
    pub rdi: u64,
    /// RBP register
    pub rbp: u64,
    /// RSP register (stack pointer)
    pub rsp: u64,
    /// R8-R15 registers
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// RIP register (instruction pointer)
    pub rip: u64,
    /// RFLAGS register
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniKvmMmio {
    pub phys_addr: u64,
    pub data: u64,
    pub len: u32,
    pub is_write: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniKvmInternalError {
    pub error_code: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniKvmRunState {
    pub exit_reason: u32,
    pub padding: u32,
    pub mmio: MiniKvmMmio,
    pub internal_error: MiniKvmInternalError,
}

// VM exit reasons
const EXIT_REASON_MMIO: u32 = 1;
const EXIT_REASON_HLT: u32 = 2;
const EXIT_REASON_SHUTDOWN: u32 = 3;
const EXIT_REASON_INTERNAL_ERROR: u32 = 4;

/// Device state holding VM and VCPU
struct RKvmDeviceData {
    vm: Option<Arc<RKvmVm>>,
    vcpu: Option<Arc<RKvmVcpu>>,
}

impl RKvmDeviceData {
    fn new() -> Self {
        Self {
            vm: None,
            vcpu: None,
        }
    }
}

/// Main device structure
pub struct RKvmDevice;

impl MiscDevice for RKvmDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        
        dev_info!(dev, "RKVM: Device opened\n");

        KBox::try_pin_init(
            try_pin_init! {
                RKvmDevice {
                    inner <- new_mutex!(Inner {
                        vm: None,
                    }),
                    dev: dev,
                }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(me: Pin<&RKvmDevice>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            RKVM_CREATE_VM => me.ioctl_create_vm()?,
            RKVM_CREATE_VCPU => me.ioctl_create_vcpu()?,
            RKVM_SET_REGS => me.ioctl_set_regs(arg)?,
            RKVM_SET_MEM => me.ioctl_set_mem(arg)?,
            RKVM_RUN => me.ioctl_run(arg)?,
            _ => {
                dev_err!(me.dev, "RKVM: Unknown ioctl command: 0x{:x}\n", cmd);
                return Err(ENOTTY);
            }
        };

        Ok(0)
    }
}

impl RKvmDevice {
    /// Create a new VM
    fn create_vm(&self) -> Result<isize> {
        let mut guard = self.inner.lock();
        
        if guard.vm.is_some() {
            dev_err!(self.dev, "RKVM: VM already created\n");
            return Err(EEXIST);
        }
        
        let vm = RKvmVm::new()?;
        guard.vm = Some(vm);
        
        dev_info!(self.dev, "RKVM: VM created successfully\n");
        Ok(0)
    }
    
    /// Create a vCPU
    fn create_vcpu(&self) -> Result<isize> {
        let mut guard = self.inner.lock();
        
        let vm = guard.vm.as_mut().ok_or_else(|| {
            dev_err!(self.dev, "RKVM: VM not created\n");
            EINVAL
        })?;
        
        vm.create_vcpu()?;
        
        dev_info!(self.dev, "RKVM: vCPU created successfully\n");
        Ok(0)
    }

    /// Set guest registers
    fn ioctl_set_regs(&self, arg: usize) -> Result<isize> {
        let guard = self.inner.lock();
        let vcpu = guard.vcpu.as_ref().ok_or(EINVAL)?;
        // Copy registers from userspace
        let user_ptr = arg as *const RegsMessage;
        let mut regs = RegsMessage::default();
        
        unsafe {
            if user_ptr.is_null() {
                return Err(EINVAL);
            }
            core::ptr::copy_nonoverlapping(
                user_ptr,
                &mut regs as *mut RegsMessage,
                1,
            );
        }

        // Convert to GuestRegs
        let guest_regs = GuestRegs {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        };

        pr_info!("RKVM-x86: Setting RIP=0x{:x}, RSP=0x{:x}\n", 
                 guest_regs.rip, guest_regs.rsp);

        vcpu.set_regs(&guest_regs)?;
        Ok(0)
    }

    /// Get guest registers
    fn ioctl_get_regs(&self, arg: usize) -> Result<isize> {

        Ok(0)
    }

    
    fn ioctl_set_mem(&self, arg: usize) -> Result<isize> {
        let mut guard = self.inner.lock();
        let vm = guard.vm.as_mut().ok_or(EINVAL)?;

        // Copy memory region info from userspace
        let user_ptr = arg as *const GuestMemoryMapMessage;
        let mut region = GuestMemoryMapMessage {
            host_virt_addr: 0,
            guest_phys_addr: 0,
            memory_size: 0,
        };

        unsafe {
            if user_ptr.is_null() {
                pr_err!("RKVM-x86: SET_MEM: null pointer\n");
                return Err(EINVAL);
            }
            core::ptr::copy_nonoverlapping(
                user_ptr,
                &mut region as *mut GuestMemoryMapMessage,
                1,
            );
        }

        // Validate parameters
        let size = region.memory_size;
        if size == 0 {
            pr_err!("RKVM-x86: SET_MEM: zero size\n");
            return Err(EINVAL);
        }
        
        if size > 16 * 1024 * 1024 {
            pr_err!("RKVM-x86: SET_MEM: size too large: {} bytes\n", size);
            return Err(EINVAL);
        }
        
        if region.host_virt_addr == 0 {
            pr_err!("RKVM-x86: SET_MEM: null host virtual address\n");
            return Err(EINVAL);
        }

        pr_info!("RKVM-x86: SET_MEM ioctl:\n");
        pr_info!("  Host VA: 0x{:x}\n", region.host_virt_addr);
        pr_info!("  Guest PA: 0x{:x}\n", region.guest_phys_addr);
        pr_info!("  Size: {} bytes ({} MB)\n", size, size / (1024 * 1024));

        // Set memory in VM (this will map it in EPT)
        vm.set_memory(region)?;

        pr_info!("RKVM-x86: SET_MEM completed successfully\n");
        Ok(0)
    }

    /// Run VCPU
    fn ioctl_run(&self, arg: usize) -> Result<isize> {
        let guard = self.inner.lock();
        let vcpu = guard.vcpu.as_ref().ok_or(EINVAL)?;

        // Run the VCPU
        let exit_reason = vcpu.run()?;

        // Create run state
        let mut run_state = MiniKvmRunState {
            exit_reason,
            padding: 0,
            mmio: MiniKvmMmio {
                phys_addr: 0,
                data: 0,
                len: 0,
                is_write: 0,
                padding: [0; 3],
            },
            internal_error: MiniKvmInternalError {
                error_code: 0,
                padding: 0,
            },
        };

        // Copy to userspace
        let user_ptr = arg as *mut MiniKvmRunState;
        unsafe {
            if user_ptr.is_null() {
                return Err(EINVAL);
            }
            core::ptr::copy_nonoverlapping(
                &run_state as *const MiniKvmRunState,
                user_ptr,
                1,
            );
        }

        Ok(0)
    }
}

/// Registration structure
pub struct RKvmDeviceRegistration {
    _reg: Pin<Box<miscdev::Registration<RKvmDevice>>>,
}

impl RKvmDeviceRegistration {
    pub fn register() -> Result<Self> {
        pr_info!("RKVM-x86: Registering /dev/rkvm device\n");

        let reg = miscdev::Registration::new_pinned(
            c_str!("rkvm"),
        )?;

        Ok(Self { _reg: reg })
    }
}

impl Drop for RKvmDeviceRegistration {
    fn drop(&mut self) {
        pr_info!("RKVM-x86: Unregistered /dev/rkvm device\n");
    }
}

// ioctl helper macros
macro_rules! _IO {
    ($magic:expr, $nr:expr) => {
        ((0u32 << 30) | (($magic as u32) << 8) | ($nr as u32))
    };
}

macro_rules! _IOR {
    ($magic:expr, $nr:expr, $ty:ty) => {
        ((2u32 << 30) | ((mem::size_of::<$ty>() as u32) << 16) | 
         (($magic as u32) << 8) | ($nr as u32))
    };
}

macro_rules! _IOW {
    ($magic:expr, $nr:expr, $ty:ty) => {
        ((1u32 << 30) | ((mem::size_of::<$ty>() as u32) << 16) | 
         (($magic as u32) << 8) | ($nr as u32))
    };
}

use _IO;
use _IOR;
use _IOW;