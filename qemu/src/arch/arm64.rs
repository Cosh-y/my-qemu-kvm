/*
 * arch/arm64.rs - ARM64 (AArch64) architecture support
 * 
 * Defines ARM64-specific register structures and initialization.
 */

use super::ArchRegs;

/// ARM64 general purpose registers and CPU state
/// Must match the kernel module's MiniKvmRegs structure
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct Arm64Regs {
    /// General purpose registers x0-x30
    pub x: [u64; 31],
    /// Program counter
    pub pc: u64,
    /// Processor state (PSTATE/CPSR)
    pub pstate: u64,
    /// Stack pointer
    pub sp: u64,
}

impl ArchRegs for Arm64Regs {
    fn pc(&self) -> u64 {
        self.pc
    }
    
    fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }
    
    fn sp(&self) -> u64 {
        self.sp
    }
    
    fn set_sp(&mut self, sp: u64) {
        self.sp = sp;
    }
    
    fn init_for_entry(entry: u64, stack: u64) -> Self {
        let mut regs = Arm64Regs::default();
        regs.pc = entry;
        regs.sp = stack;
        // PSTATE: EL1h, IRQ/FIQ masked
        // D=1 (Debug masked), A=1 (SError masked), I=1 (IRQ masked), F=1 (FIQ masked)
        // M[4:0]=0b00101 (EL1h)
        regs.pstate = 0x3c5;
        regs
    }
}

/// Type alias for architecture-specific registers
pub type MiniKvmRegs = Arm64Regs;