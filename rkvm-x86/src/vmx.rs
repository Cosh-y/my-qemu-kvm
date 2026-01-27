//! VMX (Virtual Machine Extensions) operations for Intel VT-x
//! 
//! This module provides wrappers for VMX instructions and VMCS access

use crate::types::*;
use kernel::prelude::*;

/// VMCS revision identifier (read from MSR)
static mut VMCS_REVISION: u32 = 0;

/// Initialize VMX support
pub fn init_vmx() -> Result<()> {
    // Check CPUID for VMX support
    unsafe {
        let cpuid_result = core::arch::x86_64::__cpuid(1);
        if (cpuid_result.ecx & (1 << 5)) == 0 {
            pr_err!("VMX not supported by CPU\n");
            return Err(ENODEV);
        }
    }
    
    // Read VMX basic MSR to get VMCS revision ID
    unsafe {
        let msr_value = rdmsr(0x480); // IA32_VMX_BASIC
        VMCS_REVISION = (msr_value & 0x7FFFFFFF) as u32;
        pr_info!("VMCS revision: 0x{:x}\n", VMCS_REVISION);
    }
    
    on_each_cpu(|| {
        // Enable VMX in CR4
        unsafe {
            let mut cr4: u64;
            core::arch::asm!(
                "mov {}, cr4",
                out(reg) cr4,
                options(nomem, nostack)
            );
            cr4 |= 1 << 13; // CR4.VMXE
            core::arch::asm!(
                "mov cr4, {}",
                in(reg) cr4,
                options(nostack)
            );
        }

        // Allocate VMXON region and execute VMXON
        let _vmxon_region = alloc_vmxon_region()?;
        unsafe {
            vmxon(_vmxon_region)?;
        }
    })?;
    
    pr_info!("VMX initialized successfully\n");
    Ok(())
}

/// Read MSR
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Write MSR
#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nostack)
    );
}

/// Execute VMXON
#[inline]
pub unsafe fn vmxon(vmxon_region: PhysAddr) -> Result<()> {
    let mut rflags: u64;
    core::arch::asm!(
        "vmxon [{}]",
        "pushfq",
        "pop {}",
        in(reg) &vmxon_region,
        out(reg) rflags,
        options(nostack)
    );
    
    // Check CF (bit 0) and ZF (bit 6)
    if (rflags & 1) != 0 {
        return Err(EINVAL); // VMfailInvalid
    }
    if (rflags & (1 << 6)) != 0 {
        return Err(EIO); // VMfailValid
    }
    
    Ok(())
}

/// Execute VMXOFF
#[inline]
pub unsafe fn vmxoff() -> Result<()> {
    let mut rflags: u64;
    core::arch::asm!(
        "vmxoff",
        "pushfq",
        "pop {}",
        out(reg) rflags,
        options(nostack)
    );
    
    if (rflags & 1) != 0 {
        return Err(EINVAL);
    }
    
    Ok(())
}

/// Execute VMCLEAR
#[inline]
pub unsafe fn vmclear(vmcs: u64) -> Result<()> {
    let mut rflags: u64;
    core::arch::asm!(
        "vmclear [{}]",
        "pushfq",
        "pop {}",
        in(reg) &vmcs,
        out(reg) rflags,
        options(nostack)
    );
    
    if (rflags & 1) != 0 {
        return Err(EINVAL);
    }
    if (rflags & (1 << 6)) != 0 {
        return Err(EIO);
    }
    
    Ok(())
}

/// Execute VMPTRLD
#[inline]
pub unsafe fn vmptrld(vmcs: u64) -> Result<()> {
    let mut rflags: u64;
    core::arch::asm!(
        "vmptrld [{}]",
        "pushfq",
        "pop {}",
        in(reg) &vmcs,
        out(reg) rflags,
        options(nostack)
    );
    
    if (rflags & 1) != 0 {
        return Err(EINVAL);
    }
    if (rflags & (1 << 6)) != 0 {
        return Err(EIO);
    }
    
    Ok(())
}

/// Read VMCS field
#[inline]
pub unsafe fn vmread(field: u32) -> Result<u64> {
    let value: u64;
    let mut rflags: u64;
    core::arch::asm!(
        "vmread {}, {}",
        "pushfq",
        "pop {}",
        out(reg) value,
        in(reg) field as u64,
        out(reg) rflags,
        options(nomem, nostack)
    );
    
    if (rflags & 1) != 0 {
        return Err(EINVAL);
    }
    if (rflags & (1 << 6)) != 0 {
        return Err(EIO);
    }
    
    Ok(value)
}

/// Write VMCS field
#[inline]
pub unsafe fn vmwrite(field: u32, value: u64) -> Result<()> {
    let mut rflags: u64;
    core::arch::asm!(
        "vmwrite {}, {}",
        "pushfq",
        "pop {}",
        in(reg) field as u64,
        in(reg) value,
        out(reg) rflags,
        options(nostack)
    );
    
    if (rflags & 1) != 0 {
        return Err(EINVAL);
    }
    if (rflags & (1 << 6)) != 0 {
        return Err(EIO);
    }
    
    Ok(())
}

/// Allocate and initialize VMCS region
pub fn alloc_vmcs() -> Result<u64> {
    use kernel::page::alloc_pages;
    
    // Allocate 4KB page for VMCS
    let page = alloc_pages(0)?; // order 0 = 1 page
    let virt_addr = page.virt_addr();
    let phys_addr = page.phys_addr();
    
    unsafe {
        // Write VMCS revision identifier
        let ptr = virt_addr as *mut u32;
        *ptr = VMCS_REVISION;
        
        // Clear rest of page
        core::ptr::write_bytes((virt_addr + 4) as *mut u8, 0, 4096 - 4);
    }
    
    Ok(phys_addr)
}

/// Allocate and initialize VMXON region
pub fn alloc_vmxon_region() -> Result<PhysAddr> {
    use kernel::page::alloc_pages;
    
    // Allocate 4KB page for VMXON region
    let page = alloc_pages(0)?;
    let virt_addr = page.virt_addr();
    let phys_addr = page.phys_addr();
    
    unsafe {
        // Write VMCS revision identifier (same format as VMCS)
        let ptr = virt_addr as *mut u32;
        *ptr = VMCS_REVISION;
        
        // Clear rest of page
        core::ptr::write_bytes((virt_addr + 4) as *mut u8, 0, 4096 - 4);
    }
    
    Ok(phys_addr)
}

/// Get VMCS revision ID
pub fn get_vmcs_revision() -> u32 {
    unsafe { VMCS_REVISION }
}

/// Adjust control value based on VMX capability MSR
/// 
/// According to Intel SDM, control fields have reserved bits that must be set correctly:
/// - Low 32 bits of capability MSR: bits that must be 1 (allowed-0 settings)
/// - High 32 bits of capability MSR: bits that may be 1 (allowed-1 settings)
/// 
/// Formula: val = (val | low) & high
pub unsafe fn adjust_vmx_controls(desired: u32, msr: u32) -> u32 {
    let msr_value = rdmsr(msr);
    let allowed0 = (msr_value & 0xFFFFFFFF) as u32; // Low 32 bits: must be 1
    let allowed1 = (msr_value >> 32) as u32;        // High 32 bits: may be 1
    
    // Set all bits that must be 1, and clear all bits that must be 0
    (desired | allowed0) & allowed1
}

/// Adjust pin-based VM-execution controls
pub unsafe fn adjust_pin_based_controls(desired: u32) -> u32 {
    adjust_vmx_controls(desired, 0x481) // IA32_VMX_PINBASED_CTLS
}

/// Adjust primary processor-based VM-execution controls
pub unsafe fn adjust_cpu_based_controls(desired: u32) -> u32 {
    adjust_vmx_controls(desired, 0x482) // IA32_VMX_PROCBASED_CTLS
}

/// Adjust secondary processor-based VM-execution controls
pub unsafe fn adjust_secondary_controls(desired: u32) -> u32 {
    adjust_vmx_controls(desired, 0x48B) // IA32_VMX_PROCBASED_CTLS2
}

/// Adjust VM-exit controls
pub unsafe fn adjust_exit_controls(desired: u32) -> u32 {
    adjust_vmx_controls(desired, 0x483) // IA32_VMX_EXIT_CTLS
}

/// Adjust VM-entry controls
pub unsafe fn adjust_entry_controls(desired: u32) -> u32 {
    adjust_vmx_controls(desired, 0x484) // IA32_VMX_ENTRY_CTLS
}
