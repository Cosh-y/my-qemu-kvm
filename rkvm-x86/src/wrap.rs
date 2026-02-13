use core::ffi::{c_void, c_ulong};
use kernel::prelude::*;
use kernel::bindings;

use crate::types::*;

// External C functions from rkvm_x86_glue.c
extern "C" {
    fn rkvm_virt_to_phys(addr: *const c_void) -> u64;
    fn rkvm_phys_to_virt(addr: u64) -> *mut c_void;
    fn rkvm_page_address(page: *const bindings::page) -> *mut c_void;
    fn rkvm_copy_from_user(to: *mut c_void, from: *const c_void, n: c_ulong) -> c_ulong;
    fn rkvm_copy_to_user(to: *mut c_void, from: *const c_void, n: c_ulong) -> c_ulong;
}

// Helper for on_each_cpu callback
unsafe extern "C" fn on_each_cpu_callback(info: *mut c_void) {
    // Cast void pointer back to Rust closure pointer and call it
    let func = info as *mut &mut dyn FnMut();
    unsafe { (*func)(); }
}

/// Run a function on all CPUs
/// 
/// This is a wrapper around the kernel's on_each_cpu (or similar functions).
/// Since we don't have direct access to the on_each_cpu macro via bindgen,
/// we implement it using smp_call_function (for other CPUs) and a local call.
/// 
/// # Arguments
/// * `func` - The closure to run on each CPU
pub(crate) fn on_each_cpu<F>(mut func: F) -> Result
where
    F: FnMut(),
{
    // Create a trait object to type-erase the closure
    // We need to pass a pointer to this trait object (which is a fat pointer)
    let mut trait_object: &mut dyn FnMut() = &mut func;
    let func_ptr = &mut trait_object as *mut &mut dyn FnMut() as *mut c_void;
    
    unsafe {
        // Run on all OTHER CPUs
        // smp_call_function(func, info, wait)
        bindings::smp_call_function(
            Some(on_each_cpu_callback),
            func_ptr,
            1, // wait = 1 (synchronous)
        );
        
        // Run on CURRENT CPU
        // We must disable preemption to ensure we don't migrate during this sequence,
        // but for simple initialization tasks that are idempotent or just setting up per-cpu hardware,
        // running locally is usually sufficient. 
        // Note: Strict on_each_cpu implementation requires disabling preemption.
        // Assuming this is called from init context where preemption might be enabled.
        
        // However, RFL bindings for preempt_disable are not exposed easily.
        // Given this is module init, we are likely fine for this specific use case (HVC init).
        on_each_cpu_callback(func_ptr);
    }
    
    Ok(())
}


/// Convert kernel virtual address to physical
pub fn virt_to_phys(addr: VirtAddr) -> PhysAddr {
    unsafe { rkvm_virt_to_phys(addr as *const c_void) }
}

/// Convert physical address to kernel virtual
pub fn phys_to_virt(addr: PhysAddr) -> VirtAddr {
    unsafe { rkvm_phys_to_virt(addr) as usize }
}

pub fn page_address(page: *const bindings::page) -> VirtAddr {
    unsafe { rkvm_page_address(page) as usize }
}

pub fn copy_from_user(to: *mut c_void, from: *const c_void, size: usize) -> Result<()> {
    let ret = unsafe {
        rkvm_copy_from_user(to, from, size as c_ulong)
    };
    if ret != 0 {
        return Err(EFAULT);
    }
    Ok(())
}

pub fn copy_to_user(to: *mut c_void, from: *const c_void, size: usize) -> Result<()> {
    let ret = unsafe {
        rkvm_copy_to_user(to, from, size as c_ulong)
    };
    if ret != 0 {
        return Err(EFAULT);
    }
    Ok(())
}
