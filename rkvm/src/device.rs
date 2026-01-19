//! Device file interface for /dev/rkvm
//! 
//! This module implements the character device interface and ioctl handlers
//! for the RKVM hypervisor, mirroring the functionality of mini_kvm_module.c

use core::pin::Pin;
use kernel::prelude::*;
use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOR, _IOW},
    miscdevice::{MiscDevice, MiscDeviceRegistration},
    new_mutex,
    sync::{aref::ARef, Mutex},
    uaccess::UserSlice,
    transmute::{FromBytes, AsBytes},
};
use crate::vm::RKvmVm;
use crate::types::*;
use crate::wrap::*;


/// ioctl magic number
const RKVM_MAGIC: u32 = 0xAE;

/// ioctl commands
const RKVM_CREATE_VM: u32 = _IO(RKVM_MAGIC, 1);
const RKVM_CREATE_VCPU: u32 = _IO(RKVM_MAGIC, 2);
const RKVM_RUN: u32 = _IOR::<RunState>(RKVM_MAGIC, 3);
const RKVM_SET_REGS: u32 = _IOW::<KvmCpuRegs>(RKVM_MAGIC, 4);
const RKVM_GET_REGS: u32 = _IOR::<KvmCpuRegs>(RKVM_MAGIC, 5);
const RKVM_SET_MEM: u32 = _IOW::<MemRegion>(RKVM_MAGIC, 6);

/// Memory region structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MemRegion {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

// SAFETY: MemRegion contains no padding bytes and all fields are u64, so any bit pattern is valid.
unsafe impl FromBytes for MemRegion {}
unsafe impl AsBytes for MemRegion {}

/// Inner state protected by mutex
struct Inner {
    vm: Option<RKvmVm>,
}

/// Device structure for /dev/rkvm
#[pin_data(PinnedDrop)]
pub struct RKvmDevice {
    #[pin]
    inner: Mutex<Inner>,
    dev: ARef<Device>,
}

#[vtable]
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
        // dev_info!(me.dev, "RKVM: IOCTL command 0x{:x}\n", cmd);
        
        match cmd {
            RKVM_CREATE_VM => me.create_vm()?,
            RKVM_CREATE_VCPU => me.create_vcpu()?,
            RKVM_SET_REGS => me.set_regs(arg)?,
            RKVM_GET_REGS => me.get_regs(arg)?,
            RKVM_SET_MEM => me.set_mem(arg)?,
            RKVM_RUN => me.run(arg)?,
            _ => {
                dev_err!(me.dev, "RKVM: Unknown ioctl command: 0x{:x}\n", cmd);
                return Err(ENOTTY);
            }
        };
        
        Ok(0)
    }
}

#[pinned_drop]
impl PinnedDrop for RKvmDevice {
    fn drop(self: Pin<&mut Self>) {
        dev_info!(self.dev, "RKVM: Device closed\n");
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
    fn set_regs(&self, arg: usize) -> Result<isize> {
        let mut guard = self.inner.lock();
        
        let vm = guard.vm.as_mut().ok_or_else(|| {
            dev_err!(self.dev, "RKVM: VM not created\n");
            EINVAL
        })?;
        
        let vcpu = vm.vcpu_mut()?;
        
        // Read registers from userspace
        let user_ptr = kernel::uaccess::UserPtr::from_addr(arg);
        let size = core::mem::size_of::<KvmCpuRegs>();
        let mut reader = UserSlice::new(user_ptr, size).reader();
        
        let regs = reader.read::<KvmCpuRegs>()?;
        
        // Update vCPU registers
        vcpu.regs = regs;
        
        // CRITICAL: Sync SP to system register SP_EL1
        vcpu.sys_regs.sp_el1 = regs.sp;
        
        dev_info!(self.dev, "RKVM: Set guest PC=0x{:x}, SP=0x{:x}\n", 
                  vcpu.regs.pc, vcpu.regs.sp);
        
        Ok(0)
    }
    
    /// Get guest registers
    fn get_regs(&self, arg: usize) -> Result<isize> {
        let guard = self.inner.lock();
        
        let vm = guard.vm.as_ref().ok_or_else(|| {
            dev_err!(self.dev, "RKVM: VM not created\n");
            EINVAL
        })?;
        
        let vcpu = vm.vcpu()?;
        
        // Write registers to userspace
        let user_ptr = kernel::uaccess::UserPtr::from_addr(arg);
        let size = core::mem::size_of::<KvmCpuRegs>();
        let mut writer = UserSlice::new(user_ptr, size).writer();
        
        writer.write::<KvmCpuRegs>(&vcpu.regs)?;
        
        dev_info!(self.dev, "RKVM: Get guest PC=0x{:x}, SP=0x{:x}\n",
                  vcpu.regs.pc, vcpu.regs.sp);
        
        Ok(0)
    }
    
    /// Set memory region
    fn set_mem(&self, arg: usize) -> Result<isize> {
        let mut guard = self.inner.lock();
        
        let vm = guard.vm.as_mut().ok_or_else(|| {
            dev_err!(self.dev, "RKVM: VM not created\n");
            EINVAL
        })?;
        
        // Read memory region from userspace
        let user_ptr = kernel::uaccess::UserPtr::from_addr(arg);
        let size = core::mem::size_of::<MemRegion>();
        let mut reader = UserSlice::new(user_ptr, size).reader();
        
        let region = reader.read::<MemRegion>()?;
        
        dev_info!(self.dev, "RKVM: Set memory region: GPA=0x{:x}, size=0x{:x}, UVA=0x{:x}\n",
                  region.guest_phys_addr, region.memory_size, region.userspace_addr);
        
        vm.set_memory(
            region.guest_phys_addr,
            region.userspace_addr as VirtAddr,
            region.memory_size as MemSize
        )?;
        
        Ok(0)
    }
    
    /// Run the vCPU
    fn run(&self, arg: usize) -> Result<isize> {
        let mut guard = self.inner.lock();
        
        let vm = guard.vm.as_mut().ok_or_else(|| {
            dev_err!(self.dev, "RKVM: VM not created\n");
            EINVAL
        })?;
        
        let vcpu = vm.vcpu_mut()?;
        
        // Run vCPU via HVC call
        let vcpu_vaddr = vcpu as *const _ as VirtAddr;
        let vcpu_phys = virt_to_phys(vcpu_vaddr);
        
        // Clean dcache for vcpu struct to ensure EL2 sees correct data
        crate::wrap::clean_dcache_poc(vcpu_vaddr, core::mem::size_of::<crate::vcpu::RKvmVcpu>());
        
        let ret = crate::hvc::vcpu_run(vcpu_phys)
            .unwrap_or_else(|_| -1);
        
        // Prepare run state
        let mut run_state = RunState::new();
        
        if ret != 0 {
            dev_err!(self.dev, "RKVM: vCPU run failed with {}\n", ret);
            run_state.exit_reason = ExitReason::InternalError as u32;
            run_state.internal_error.error_code = ret as u32;
        } else {
            // Handle VM exit
            self.handle_vm_exit(vcpu, &mut run_state)?;
        }
        
        // Write run state to userspace
        let user_ptr = kernel::uaccess::UserPtr::from_addr(arg);
        let size = core::mem::size_of::<RunState>();
        let mut writer = UserSlice::new(user_ptr, size).writer();
        
        writer.write::<RunState>(&run_state)?;
        
        Ok(0)
    }
    
    /// Handle VM exit
    fn handle_vm_exit(&self, vcpu: &mut crate::vcpu::RKvmVcpu, run_state: &mut RunState) -> Result {
        let esr = vcpu.esr_el2;
        let esr_ec = (esr >> 26) & 0x3F;
        match esr_ec {
            0x24 | 0x20 => {
                // Data Abort or Instruction Abort from lower EL
                // Stage-2 fault - treat as MMIO
                // For Data Abort, DFSC is in bits [5:0]
                // 0x4 means translation fault level 0
                // 0x5 means translation fault level 1
                // 0x6 means translation fault level 2
                // 0x7 means translation fault level 3
                // 0x10 means synchronous external abort (not translation table walk)
                
                run_state.exit_reason = ExitReason::Mmio as u32;
                run_state.mmio.phys_addr = vcpu.far_el2;
                
                // Get access size from ISV bit in ESR_EL2?
                // For now, if it's a Stage-2 data abort:
                // ISV is bit 24. If ISV=1, SAS (bits 23:22) gives size.
                // 00=byte, 01=half, 10=word, 11=double
                let sas = (esr >> 22) & 3;
                let len = 1 << sas;
                run_state.mmio.len = len;


                run_state.mmio.is_write = if esr_ec == 0x24 && (esr & (1 << 6)) != 0 { 1 } else { 0 };
                // Also need to get Write Data for MMIO writes (from source register)
                // For a write (WnR=1), we need the register value
                // In a real KVM, we'd need to decode the instruction or use SRT bit
                // SRT (bits 20:16) gives the register number
                
                let rt = (esr >> 16) & 0x1F;
                run_state.mmio.data = vcpu.regs.x[rt as usize];
                
                // Advance PC past faulting instruction
                vcpu.regs.pc += 4;
            }
            0x01 => {
                // WFI/WFE instruction
                pr_info!("RKVM: WFI/WFE trapped\n");
                run_state.exit_reason = ExitReason::Hlt as u32;
                vcpu.regs.pc += 4;
            }
            _ => {
                pr_warn!("RKVM: Unknown exit reason, EC=0x{:x}\n", esr_ec);
                run_state.exit_reason = ExitReason::Unknown as u32;
            }
        }
        
        Ok(())
    }
    
}

unsafe impl Send for RKvmDevice {}
unsafe impl Sync for RKvmDevice {}
