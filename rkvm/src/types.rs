//! Core data structures for RKVM
//! 
//! This module defines the data structures used throughout the KVM implementation,
//! mirroring the C structures from kvm_hyp.h

#![allow(missing_docs)]

use kernel::transmute::{FromBytes, AsBytes};

/// 物理地址类型（主机物理地址）
pub type PhysAddr = u64;

/// 虚拟地址类型（内核虚拟地址）
pub type VirtAddr = usize;

/// 客户机物理地址类型（IPA - Intermediate Physical Address）
pub type GuestPhysAddr = u64;

/// 内存大小类型
pub type MemSize = usize;

// VCPU structure offsets (must match assembly code)
pub const VCPU_REGS_OFFSET: usize = 0;
pub const VCPU_SYSREGS_OFFSET: usize = 512;
pub const VCPU_VTTBR_OFFSET: usize = 1024;
pub const VCPU_HCR_OFFSET: usize = 1032;
pub const VCPU_ESR_OFFSET: usize = 1040;
pub const VCPU_FAR_OFFSET: usize = 1048;
pub const VCPU_HPFAR_OFFSET: usize = 1056;
pub const VCPU_VTCR_OFFSET: usize = 1064;

/// System register offsets within sysregs structure
pub const SYSREG_SCTLR_EL1: usize = 0;
pub const SYSREG_TTBR0_EL1: usize = 8;
pub const SYSREG_TTBR1_EL1: usize = 16;
pub const SYSREG_TCR_EL1: usize = 24;
pub const SYSREG_MAIR_EL1: usize = 32;
pub const SYSREG_VBAR_EL1: usize = 40;
pub const SYSREG_SP_EL1: usize = 48;
pub const SYSREG_ELR_EL1: usize = 56;
pub const SYSREG_SPSR_EL1: usize = 64;

/// Per-CPU host context
pub const MAX_CPUS: usize = 8;
pub const HOST_REGS_SIZE: usize = 96;
pub const HOST_SYSREGS_SIZE: usize = 96;
pub const HOST_CONTEXT_SIZE: usize = HOST_REGS_SIZE + HOST_SYSREGS_SIZE;
pub const HOST_REGS_OFFSET: usize = 0;
pub const HOST_SYSREGS_OFFSET: usize = 96;

/// Guest CPU register state
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmCpuRegs {
    pub x: [u64; 31],
    pub pc: u64,
    pub pstate: u64,
    pub sp: u64,
}

impl KvmCpuRegs {
    pub fn new() -> Self {
        Self {
            x: [0; 31],
            pc: 0,
            pstate: 0,
            sp: 0,
        }
    }
}

/// Guest system registers (EL1 state)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KvmSysRegs {
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
    pub sp_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub par_el1: u64,
    pub contextidr_el1: u64,
    pub tpidr_el1: u64,
    pub tpidrro_el1: u64,
    pub amair_el1: u64,
}

impl KvmSysRegs {
    pub fn new() -> Self {
        Self {
            sctlr_el1: 0x30C50830, // MMU off, caches off, default bits
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            mair_el1: 0,
            vbar_el1: 0,
            sp_el1: 0,
            elr_el1: 0,
            spsr_el1: 0,
            esr_el1: 0,
            far_el1: 0,
            par_el1: 0,
            contextidr_el1: 0,
            tpidr_el1: 0,
            tpidrro_el1: 0,
            amair_el1: 0,
        }
    }
}

/// Stage-2 page table entry
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct S2Pte(pub u64);

impl S2Pte {
    pub const VALID: u64 = 1 << 0;
    pub const TABLE: u64 = 1 << 1;
    pub const AF: u64 = 1 << 10;
    pub const SH_INNER: u64 = 3 << 8;
    pub const S2AP_RW: u64 = 3 << 6;
    pub const MEMATTR_DEV: u64 = 0 << 2;
    pub const MEMATTR_NORM: u64 = 0xF << 2;
    
    pub fn new() -> Self {
        Self(0)
    }
    
    pub fn is_valid(&self) -> bool {
        (self.0 & Self::VALID) != 0
    }
    
    pub fn addr(&self) -> u64 {
        self.0 & !0xFFF
    }
}

/// Page table configuration
pub const S2_PGDIR_SHIFT: usize = 30;
pub const S2_PUD_SHIFT: usize = 21;
pub const S2_PMD_SHIFT: usize = 12;
pub const S2_PTRS_PER_TABLE: usize = 512;

/// Stage-2 translation configuration
pub const S2_VTCR_PS_40BIT: u64 = 2 << 16;
pub const S2_VTCR_TG0_4K: u64 = 0 << 14;
pub const S2_VTCR_SH0_INNER: u64 = 3 << 12;
pub const S2_VTCR_ORGN0_WBWA: u64 = 1 << 10;
pub const S2_VTCR_IRGN0_WBWA: u64 = 1 << 8;
pub const S2_VTCR_SL0_L1: u64 = 1 << 6;
pub const S2_VTCR_T0SZ_25BIT: u64 = 25 << 0;

/// HCR_EL2 configuration flags
pub const HCR_VM: u64 = 1 << 0;
pub const HCR_SWIO: u64 = 1 << 1;
pub const HCR_PTW: u64 = 1 << 2;
pub const HCR_FMO: u64 = 1 << 3;
pub const HCR_IMO: u64 = 1 << 4;
pub const HCR_AMO: u64 = 1 << 5;
pub const HCR_TWI: u64 = 1 << 13;
pub const HCR_TSC: u64 = 1 << 19;
pub const HCR_RW: u64 = 1 << 31;

pub const HCR_GUEST_FLAGS: u64 = HCR_VM | HCR_RW | HCR_IMO | HCR_FMO | HCR_AMO | HCR_TWI | HCR_TSC;

/// VM exit reasons
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Unknown = 0,
    Mmio = 1,
    Hlt = 2,
    Shutdown = 3,
    InternalError = 4,
}

/// MMIO access information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MmioAccess {
    pub phys_addr: u64,
    pub data: u64,
    pub len: u32,
    pub is_write: u8,
    pub _padding: [u8; 3],
}

impl MmioAccess {
    pub fn new() -> Self {
        Self {
            phys_addr: 0,
            data: 0,
            len: 0,
            is_write: 0,
            _padding: [0; 3],
        }
    }
}

/// Internal error information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InternalError {
    pub error_code: u32,
    pub _padding: u32,
}

/// Run state structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RunState {
    pub exit_reason: u32,
    pub _padding: u32,
    pub mmio: MmioAccess,
    pub internal_error: InternalError,
}

impl RunState {
    pub fn new() -> Self {
        Self {
            exit_reason: ExitReason::Unknown as u32,
            _padding: 0,
            mmio: MmioAccess::new(),
            internal_error: InternalError {
                error_code: 0,
                _padding: 0,
            },
        }
    }
}

// SAFETY: All fields are integral types or arrays of integral types, so any bit pattern is valid.
unsafe impl FromBytes for KvmCpuRegs {}
unsafe impl AsBytes for KvmCpuRegs {}

// SAFETY: MmioAccess contains no padding bytes and all fields accept any bit pattern.
unsafe impl FromBytes for MmioAccess {}
unsafe impl AsBytes for MmioAccess {}

// SAFETY: InternalError contains no padding bytes and all fields accept any bit pattern.
unsafe impl FromBytes for InternalError {}
unsafe impl AsBytes for InternalError {}

// SAFETY: RunState contains no padding bytes and all fields accept any bit pattern.
unsafe impl FromBytes for RunState {}
unsafe impl AsBytes for RunState {}
