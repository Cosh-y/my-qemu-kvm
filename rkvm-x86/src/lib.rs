//! RKVM-x86 - Simplified x86_64 KVM Implementation
//! 
//! This is a minimal x86_64 KVM implementation using Intel VT-x/VMX

#![no_std]

mod types;
mod wrap;
mod vmx;
mod pt;
mod ept;
mod vcpu;
mod vm;
mod device;
mod inst;
mod regs;
mod x86;

pub use types::*;
pub use vmx::*;
pub use pt::*;
pub use ept::*;
pub use vcpu::*;
pub use vm::*;
pub use wrap::*;
pub use device::*;
pub use inst::*;

module! {
    type: RkvmX86Module,
    name: "rkvm_x86",
    authors: ["Harry"],
    description: "Simplified x86_64 KVM using Intel VT-x",
    license: "GPL v2",
}

use kernel::{
    c_str,
    prelude::*,
    miscdevice::{MiscDeviceOptions, MiscDeviceRegistration},
};

struct RkvmX86Module {
    _dev: Pin<KBox<kernel::miscdevice::MiscDeviceRegistration<RKvmDevice>>>,
}

impl kernel::Module for RkvmX86Module {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("RKVM-x86: Initializing x86_64 KVM module\n");
        
        // Initialize VMX
        vmx::init_vmx()?;

        let options = MiscDeviceOptions {
            name: c_str!("rkvm_x86"),
        };
        
        pr_info!("RKVM-x86: Module loaded successfully\n");
        Ok(Self {
            _dev: KBox::pin_init(
                MiscDeviceRegistration::register(options),
                GFP_KERNEL
            )?,
        })
    }
}

impl Drop for RkvmX86Module {
    fn drop(&mut self) {
        pr_info!("RKVM-x86: Module unloaded\n");
    }
}