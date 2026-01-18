//! RKVM - Rust KVM Module for ARM64
//! 
//! This module provides hypervisor functionality using Rust with the same
//! architecture as the C implementation:
//! - EL2 initialization via HVC calls
//! - Real world switching between host (EL2) and guest (EL1)
//! - Stage-2 memory translation with page table management
//! - System register context switching

#![no_std]
#![allow(dead_code)]

mod types;
mod hvc;
mod stage2;
mod vcpu;
mod vm;
mod device;
mod wrap;

pub use types::*;
pub use hvc::*;
pub use vm::RKvmVm;
pub use device::RKvmDevice;

use core::pin::Pin;
use kernel::prelude::*;

module! {
    type: RKvmModule,
    name: "rkvm",
    authors: ["Harry"],
    description: "Rust KVM module for ARM64 with stage-2 paging",
    license: "GPL",
}

struct RKvmModule {
    _dev: Pin<KBox<kernel::miscdevice::MiscDeviceRegistration<RKvmDevice>>>,
}

impl kernel::Module for RKvmModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("RKVM: Initializing Rust KVM module with stage-2 paging\n");
        
        // Check current exception level
        let current_el = read_current_el();
        pr_info!("RKVM: Current Exception Level: EL{}\n", current_el);
        
        // Check virtualization support
        let id_aa64pfr0 = read_id_aa64pfr0_el1();
        pr_info!("RKVM: ID_AA64PFR0_EL1 = 0x{:x}\n", id_aa64pfr0);
        
        if ((id_aa64pfr0 >> 8) & 0xF) == 0 {
            pr_err!("RKVM: CPU does not support EL2/virtualization\n");
            return Err(ENODEV);
        }
        
        // Initialize EL2 via HVC calls
        if current_el == 1 {
            pr_info!("RKVM: Kernel at EL1, using HVC calls for EL2 access\n");
            hvc::init_el2_hvc()?;
        } else {
            pr_err!("RKVM: Unexpected exception level: EL{}\n", current_el);
            return Err(EINVAL);
        }
        
        // Register device
        let options = kernel::miscdevice::MiscDeviceOptions {
            name: kernel::c_str!("rkvm"),
        };
        let dev = KBox::pin_init(
            kernel::miscdevice::MiscDeviceRegistration::register(options),
            GFP_KERNEL
        )?;
        
        pr_info!("RKVM: Module loaded successfully\n");
        pr_info!("RKVM: - Real EL1 guest execution\n");
        pr_info!("RKVM: - System register context switching\n");
        pr_info!("RKVM: - Stage-2 page table management\n");
        pr_info!("RKVM: Device: /dev/rkvm\n");
        
        Ok(RKvmModule { _dev: dev })
    }
}

impl Drop for RKvmModule {
    fn drop(&mut self) {
        pr_info!("RKVM: Module unloaded\n");
    }
}

// Helper functions to read system registers
fn read_current_el() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", out(reg) val);
    }
    (val >> 2) & 3
}

fn read_id_aa64pfr0_el1() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {}, id_aa64pfr0_el1", out(reg) val);
    }
    val
}
