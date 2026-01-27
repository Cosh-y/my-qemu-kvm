/*
 * arch/x86.rs - x86_64 architecture support
 * 
 * Defines x86_64-specific register structures and initialization.
 */

use super::ArchRegs;

/// x86_64 general purpose registers and CPU state
/// Must match the kernel module's x86 register structure
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct X86Regs {
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

impl ArchRegs for X86Regs {
    fn pc(&self) -> u64 {
        self.rip
    }
    
    fn set_pc(&mut self, pc: u64) {
        self.rip = pc;
    }
    
    fn sp(&self) -> u64 {
        self.rsp
    }
    
    fn set_sp(&mut self, sp: u64) {
        self.rsp = sp;
    }
    
    fn init_for_entry(entry: u64, stack: u64) -> Self {
        let mut regs = X86Regs::default();
        regs.rip = entry;
        regs.rsp = stack;
        // RFLAGS: bit 1 is always 1, bit 9 is IF (interrupts enabled initially)
        regs.rflags = 0x2 | 0x200;
        regs
    }
}

/// Type alias for architecture-specific registers
pub type MiniKvmRegs = X86Regs;