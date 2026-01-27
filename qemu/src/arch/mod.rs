/*
 * arch/mod.rs - Architecture abstraction layer
 * 
 * This module provides a unified interface for different CPU architectures.
 * Each architecture implements the ArchRegs trait with its specific register layout.
 */

#[cfg(feature = "arch-arm64")]
pub mod arm64;
#[cfg(feature = "arch-arm64")]
pub use arm64::*;

#[cfg(feature = "arch-x86")]
pub mod x86;
#[cfg(feature = "arch-x86")]
pub use x86::*;

use std::fmt::Debug;

/// Architecture-specific register set trait
/// Each architecture must implement this to provide register access
pub trait ArchRegs: Debug + Clone + Default + Sized {
    /// Get program counter (instruction pointer)
    fn pc(&self) -> u64;
    
    /// Set program counter
    fn set_pc(&mut self, pc: u64);
    
    /// Get stack pointer
    fn sp(&self) -> u64;
    
    /// Set stack pointer
    fn set_sp(&mut self, sp: u64);
    
    /// Initialize registers for VM entry
    /// Sets up the CPU state for first execution at the given entry point
    fn init_for_entry(entry: u64, stack: u64) -> Self;
    
    /// Get the size of the register structure in bytes (for ioctl)
    fn struct_size() -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Architecture name as string
pub const ARCH_NAME: &str = {
    #[cfg(feature = "arch-arm64")]
    { "ARM64" }
    
    #[cfg(feature = "arch-x86")]
    { "x86_64" }
};