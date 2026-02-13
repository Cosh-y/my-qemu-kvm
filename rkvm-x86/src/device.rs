// device.rs - Device driver for /dev/rkvm_x86
//
// Provides ioctl interface for userspace VMM (qemu) to create and manage VMs
#![allow(missing_docs)]

use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOR, _IOW},
    prelude::*,
    sync::{aref::ARef, Mutex},
    miscdevice::{MiscDevice, MiscDeviceRegistration},
};
use core::mem;
use core::ffi::c_void;

use crate::{VmcsGuestNW, types::*};
use crate::{GuestPhysAddr, VmxExitReason, vm::{PinnedMem, X86Vm}};
use crate::vcpu::X86Vcpu;
use crate::regs::GuestRegs;
use crate::pt::{TmpPageTables, PML4_GPA};
use crate::wrap::{virt_to_phys, copy_from_user, copy_to_user};

// ioctl command numbers - must match qemu/src/mini_kvm.rs
const MINIKVM_MAGIC: u32 = 0xAE;
const RKVM_CREATE_VM: u32 = _IO(MINIKVM_MAGIC, 1);
const RKVM_CREATE_VCPU: u32 = _IO(MINIKVM_MAGIC, 2);
const RKVM_RUN: u32 = _IOR::<RunStateMessage>(MINIKVM_MAGIC, 3);
const RKVM_SET_REGS: u32 = _IOW::<RegsMessage>(MINIKVM_MAGIC, 4);
const RKVM_GET_REGS: u32 = _IOR::<RegsMessage>(MINIKVM_MAGIC, 5);
const RKVM_SET_MEM: u32 = _IOW::<GuestMemoryMapMessage>(MINIKVM_MAGIC, 6);

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
pub struct MmioInfo {
    pub phys_addr: GuestPhysAddr,
    pub data: u64,
    pub len: u32,
    pub is_write: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RunStateMessage {
    pub exit_reason: u32,
    pub mmio: MmioInfo,
}

/// Device state holding VM and VCPU
struct RKvmDeviceData {
    // TODO: remove vm ref from here, use vm_fd and vcpu_fd to manage multiple VMs/vCPUs
    pub vm: Option<X86Vm>,
}

impl RKvmDeviceData {
    fn new() -> Self {
        Self {
            vm: None,
        }
    }
}

/// Main device structure
#[pin_data(PinnedDrop)]
pub struct RKvmDevice {
    #[pin]
    inner: Mutex<RKvmDeviceData>,
    dev: ARef<Device>,
}

#[pinned_drop]
impl PinnedDrop for RKvmDevice {
    fn drop(self: Pin<&mut Self>) {
        dev_info!(self.dev, "RKVM: Device closed\n");
    }
}

#[vtable]
impl MiscDevice for RKvmDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        
        dev_info!(dev, "RKVM: Device opened\n");
        dev_info!(dev, "ioctl func codes: CREATE_VM=0x{:x}, CREATE_VCPU=0x{:x}, RUN=0x{:x}, SET_REGS=0x{:x}, GET_REGS=0x{:x}, SET_MEM=0x{:x}\n",
                  RKVM_CREATE_VM, RKVM_CREATE_VCPU, RKVM_RUN, RKVM_SET_REGS, RKVM_GET_REGS, RKVM_SET_MEM);

        KBox::try_pin_init(
            try_pin_init! {
                RKvmDevice {
                    inner <- kernel::new_mutex!(RKvmDeviceData {
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
    fn ioctl_create_vm(&self) -> Result<isize> {
        let mut guard = self.inner.lock();
        
        if guard.vm.is_some() {
            dev_err!(self.dev, "RKVM: VM already created\n");
            return Err(EEXIST);
        }
        
        let vm = X86Vm::new()?;
        guard.vm = Some(vm);
        
        dev_info!(self.dev, "RKVM: VM created successfully\n");
        Ok(0)
    }
    
    /// Create a vCPU
    fn ioctl_create_vcpu(&self) -> Result<isize> {
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
        let mut guard = self.inner.lock();
        let vm: &mut X86Vm = guard.vm.as_mut().ok_or(EINVAL)?;
        let vcpu = vm.get_vcpu_mut()?; // For simplicity, use vCPU 0
        // Copy registers from userspace
        let user_ptr = arg as *const RegsMessage;
        let mut regs = RegsMessage::default();
        
        if user_ptr.is_null() {
            return Err(EINVAL);
        }

        copy_from_user(
            &mut regs as *mut _ as *mut c_void,
            user_ptr as *const c_void,
            core::mem::size_of::<RegsMessage>(),
        )?;

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

        vcpu.set_regs(&guest_regs);
        Ok(0)
    }

    /// Get guest registers
    fn ioctl_get_regs(&self, arg: usize) -> Result<isize> {

        Ok(0)
    }

    
    fn ioctl_set_mem(&self, arg: usize) -> Result<isize> {
        let mut guard = self.inner.lock();
        let vm: &mut X86Vm = guard.vm.as_mut().ok_or(EINVAL)?;
        let vcpu = match vm.get_vcpu_mut() {
            Ok(v) => v,
            Err(_) => {
                pr_err!("RKVM-x86: SET_MEM: vCPU not created\n");
                return Err(EINVAL);
            }
        };

        // Copy memory region info from userspace
        let user_ptr = arg as *const GuestMemoryMapMessage;
        let mut region = GuestMemoryMapMessage {
            host_virt_addr: 0,
            guest_phys_addr: 0,
            memory_size: 0,
        };

        if user_ptr.is_null() {
            pr_err!("RKVM-x86: SET_MEM: null pointer\n");
            return Err(EINVAL);
        }

        copy_from_user(
            &mut region as *mut _ as *mut c_void,
            user_ptr as *const c_void,
            core::mem::size_of::<GuestMemoryMapMessage>(),
        )?;

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

        vcpu.setup_entry(region.guest_phys_addr);

        // Set memory in VM (this will map it in EPT)
        vm.set_memory(&region)?;

        // Setup page tables for IA-32e mode guest
        self.setup_guest_page_tables(vm, &region)?;

        pr_info!("RKVM-x86: SET_MEM completed successfully\n");
        Ok(0)
    }

    /// Setup guest page tables for IA-32e mode
    /// This creates temporary page tables that map the first 4GB of guest physical memory
    /// using 1GB pages and writes them to guest memory at fixed locations.
    fn setup_guest_page_tables(&self, vm: &mut X86Vm, region: &GuestMemoryMapMessage) -> Result<()> {
        pr_info!("RKVM-x86: Setting up guest page tables\n");
        
        // Create temporary page tables
        let mut pt = TmpPageTables::new()?;
        let guest_phys_base = vm.get_memory()[0].guest_phys_addr_base();
        let host_virt_base = vm.get_memory()[0].virt_addr_base();
        let size = (vm.get_memory()[0].get_pages_count() << 12) as u64;
        let load_addr = guest_phys_base + size - (2 << 12);
        let base_addr = guest_phys_base;
        pt.setup_identity_map_4GB(load_addr, base_addr)?;
        pr_info!("load_addr: 0x{:x}, base_addr: 0x{:x}\n", load_addr, base_addr);
        let host_virt_load_addr = host_virt_base + (load_addr - guest_phys_base) as usize;
        
        // Copy PML4 and PDPT to guest memory
        // guest memory is in userspace, so we must use copy_to_user
        copy_to_user(
            host_virt_load_addr as *mut c_void,
            pt.pml4_base_addr() as *const c_void,
            4096,
        )?;
        
        copy_to_user(
            (host_virt_load_addr + 0x1000) as *mut c_void,
            pt.pdpt_base_addr() as *const c_void,
            4096,
        )?;

        unsafe { PML4_GPA = load_addr; }
        Ok(())
    }

    /// Run VCPU
    /// arg: pointer(hva) to RunStateMessage in userspace, where we will write the exit reason and MMIO info
    fn ioctl_run(&self, arg: usize) -> Result<isize> {
        let mut guard = self.inner.lock();
        let vm: &mut X86Vm = guard.vm.as_mut().ok_or(EINVAL)?;
        let eptp = vm.get_eptp();
        let vcpu: &mut X86Vcpu = vm.get_vcpu_mut()?;

        // Run the VCPU
        let exit_info = vcpu.run(eptp)?;
        let exit_reason = exit_info.exit_reason;
        let mut run_state = RunStateMessage {
            exit_reason: exit_reason,
            mmio: MmioInfo {
                phys_addr: 0,
                data: 0,
                len: 0,
                is_write: 0,
            },
        };
        // Create run state
        match VmxExitReason::try_from(exit_reason) {
            Ok(VmxExitReason::EPT_VIOLATION) => {
                pr_info!("RKVM-x86: VM Exit: MMIO EPT_VIOLATION\n");
                run_state.mmio.phys_addr = exit_info.guest_phys_addr;
                let mut buf: [u8; 8] = [0; 8];
                vm.read_instruction(exit_info.guest_rip, &mut buf)?;
                
                if exit_info.exit_qualification & 0x2 != 0 {
                    use crate::inst::mov_parser;
                    let (inst_len, val) = match mov_parser(&buf) {
                        Some((len, value)) => (len, value),
                        None => {
                            pr_err!("RKVM-x86: Unsupported MMIO write instruction at RIP=0x{:x}\n", exit_info.guest_rip);
                            return Err(EINVAL);
                        }
                    };
                    run_state.mmio.is_write = 1;
                    run_state.mmio.len = inst_len as u32;
                    run_state.mmio.data = val;
                    
                    // Advance RIP to skip the instruction
                    VmcsGuestNW::RIP.write((exit_info.guest_rip + inst_len) as usize)?;
                    
                    pr_info!("MMIO Write: addr=0x{:x}, data=0x{:x}, len={}\n", 
                             run_state.mmio.phys_addr, run_state.mmio.data, run_state.mmio.len);
                } else {
                    pr_info!("MMIO Read: addr=0x{:x}\n", run_state.mmio.phys_addr);
                }
            }
            Ok(reason) => {
                pr_info!("RKVM-x86: VM Exit: {:?}\n", reason);
            }
            Err(_) => {
                pr_info!("RKVM-x86: VM Exit: Unknown reason code {}\n", exit_reason);
            }
        }

        // Copy to userspace
        let user_ptr = arg as *mut RunStateMessage;
        if user_ptr.is_null() {
            return Err(EINVAL);
        }

        copy_to_user(
            user_ptr as *mut c_void,
            &run_state as *const _ as *const c_void,
            core::mem::size_of::<RunStateMessage>(),
        )?;

        Ok(0)
    }
}
