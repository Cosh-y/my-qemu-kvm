//! HVC call interface for EL2 access from EL1
//! 
//! This module provides Rust wrappers for HVC calls to the EL2 stub,
//! mirroring the functionality from kvm_hvc.c
#![allow(missing_docs)]

use kernel::prelude::*;
use crate::types::*;
use crate::wrap::*;

/// HVC function numbers
pub const HVC_KVM_INIT_HYP: u64 = 0x100;
pub const HVC_KVM_VCPU_RUN: u64 = 0x101;
pub const HVC_KVM_WRITE_SYSREG: u64 = 0x102;
pub const HVC_KVM_READ_SYSREG: u64 = 0x103;

/// EL2 system register IDs
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum El2SysReg {
    Vtcr = 0,
    Vbar = 1,
    Hcr = 2,
    Vttbr = 3,
    Tpidr = 4,
}

/// Low-level HVC call
#[inline(always)]
fn hvc_call(func: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") func => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            options(nostack)
        );
    }
    ret
}

/// Initialize hypervisor state
pub fn init_hyp() -> Result {
    pr_info!("RKVM: Initializing hypervisor state\n");
    
    let ret = hvc_call(HVC_KVM_INIT_HYP, 0, 0, 0, 0);
    
    if ret != 0 {
        pr_err!("RKVM: HVC_KVM_INIT_HYP failed: {}\n", ret);
        return Err(EIO);
    }
    
    pr_info!("RKVM: ✓ Hypervisor state initialized (TPIDR_EL2 cleared)\n");
    Ok(())
}

/// Set VBAR_EL2 via kernel's HVC_SET_VECTORS
pub fn set_vectors(vectors: PhysAddr) -> Result {
    pr_info!("RKVM: Setting VBAR_EL2 to 0x{:x} via HVC 0\n", vectors);
    
    let ret = hvc_call(0, vectors, 0, 0, 0);
    
    if ret != 0 {
        pr_err!("RKVM: HVC SET_VECTORS failed: {}\n", ret);
        return Err(EIO);
    }
    
    Ok(())
}

/// Get VBAR_EL2 via kernel's HVC_GET_VECTORS
pub fn get_vectors() -> PhysAddr {
    hvc_call(0, 0, 0, 0, 0) as PhysAddr
}

/// Run a vCPU via HVC
pub fn vcpu_run(vcpu_phys: PhysAddr) -> Result<i32> {
    let ret = hvc_call(HVC_KVM_VCPU_RUN, vcpu_phys, 0, 0, 0);
    Ok(ret as i32)
}

/// Write an EL2 system register via HVC
pub fn write_sysreg(reg: El2SysReg, value: u64) -> Result {
    let ret = hvc_call(HVC_KVM_WRITE_SYSREG, reg as u64, value, 0, 0);
    
    if ret != 0 {
        pr_err!("RKVM: Failed to write EL2 register {:?}\n", reg);
        return Err(EIO);
    }
    
    Ok(())
}

/// Read an EL2 system register via HVC
pub fn read_sysreg(reg: El2SysReg) -> u64 {
    hvc_call(HVC_KVM_READ_SYSREG, reg as u64, 0, 0, 0) as u64
}

/// Convenience wrappers
pub fn write_vtcr_el2(value: u64) -> Result {
    write_sysreg(El2SysReg::Vtcr, value)
}

pub fn write_vbar_el2(value: u64) -> Result {
    write_sysreg(El2SysReg::Vbar, value)
}

pub fn write_hcr_el2(value: u64) -> Result {
    write_sysreg(El2SysReg::Hcr, value)
}

pub fn write_vttbr_el2(value: u64) -> Result {
    write_sysreg(El2SysReg::Vttbr, value)
}

pub fn read_vtcr_el2() -> u64 {
    read_sysreg(El2SysReg::Vtcr)
}

pub fn read_vbar_el2() -> u64 {
    read_sysreg(El2SysReg::Vbar)
}

pub fn read_hcr_el2() -> u64 {
    read_sysreg(El2SysReg::Hcr)
}

/// Initialize EL2 via HVC calls
pub fn init_el2_hvc() -> Result {
    pr_info!("RKVM: Initializing EL2 via HVC calls\n");
    
    // Get the stub vector table address from the C module's symbol
    // We'll link against the same assembly stub
    extern "C" {
        static __kvm_el2_stub_vectors: u8;
        static __kvm_el2_stub_end: u8;
    }
    
    let stub_virt = unsafe { &__kvm_el2_stub_vectors as *const u8 as VirtAddr };
    let stub_end = unsafe { &__kvm_el2_stub_end as *const u8 as VirtAddr };
    let stub_size = stub_end - stub_virt;
    
    pr_info!("RKVM: Vector table virtual: 0x{:x} - 0x{:x} (size: {} bytes)\n",
             stub_virt, stub_end, stub_size);

    // Allocate continuous physical memory for the stub
    let new_stub_virt = crate::wrap::kmalloc(stub_size, kernel::bindings::GFP_KERNEL)?;
    unsafe {
        core::ptr::copy_nonoverlapping(stub_virt as *const u8, new_stub_virt as *mut u8, stub_size);
    }

    // Clean data cache to PoC to ensure code is written to RAM
    crate::wrap::clean_dcache_poc(new_stub_virt, stub_size);
    
    // Flush instruction cache
    flush_icache_range(new_stub_virt, new_stub_virt + stub_size);

    let new_stub_phys = crate::wrap::virt_to_phys(new_stub_virt);

    pr_info!("RKVM: Relocated vector table to Phys: 0x{:x}\n", new_stub_phys);
    
    // Install our stub on all CPUs
    crate::wrap::on_each_cpu(|| {
        set_vectors(new_stub_phys).ok();
        init_hyp().ok();
    })?;
    
    // Verify VBAR_EL2
    let verify_vbar = get_vectors();
    if verify_vbar != new_stub_phys {
        pr_warn!("RKVM: VBAR_EL2 = 0x{:x} (expected 0x{:x})\n",
                verify_vbar, new_stub_phys);
    } else {
        pr_info!("RKVM: ✓ VBAR_EL2 verified\n");
    }
    
    pr_info!("RKVM: ✓ EL2 initialization complete via HVC\n");
    
    Ok(())
}
