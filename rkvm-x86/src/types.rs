//! Core data structures for x86_64 KVM implementation
//! 
//! This module defines VMX and EPT related structures for Intel VT-x

#![allow(missing_docs)]

use kernel::transmute::{FromBytes, AsBytes};

/// Physical address type
pub type PhysAddr = u64;

/// Virtual address type
pub type VirtAddr = usize;

/// Guest physical address type
pub type GuestPhysAddr = u64;

/// Memory size type
pub type MemSize = usize;

// VMCS field encodings (Intel SDM Vol 3, Appendix B)
pub const VMCS_GUEST_ES_SELECTOR: u32 = 0x00000800;
pub const VMCS_GUEST_CS_SELECTOR: u32 = 0x00000802;
pub const VMCS_GUEST_SS_SELECTOR: u32 = 0x00000804;
pub const VMCS_GUEST_DS_SELECTOR: u32 = 0x00000806;
pub const VMCS_GUEST_FS_SELECTOR: u32 = 0x00000808;
pub const VMCS_GUEST_GS_SELECTOR: u32 = 0x0000080A;
pub const VMCS_GUEST_LDTR_SELECTOR: u32 = 0x0000080C;
pub const VMCS_GUEST_TR_SELECTOR: u32 = 0x0000080E;

pub const VMCS_GUEST_CR0: u32 = 0x00006800;
pub const VMCS_GUEST_CR3: u32 = 0x00006802;
pub const VMCS_GUEST_CR4: u32 = 0x00006804;
pub const VMCS_GUEST_DR7: u32 = 0x0000681A;
pub const VMCS_GUEST_RSP: u32 = 0x0000681C;
pub const VMCS_GUEST_RIP: u32 = 0x0000681E;
pub const VMCS_GUEST_RFLAGS: u32 = 0x00006820;

pub const VMCS_GUEST_GDTR_BASE: u32 = 0x00006816;
pub const VMCS_GUEST_GDTR_LIMIT: u32 = 0x00004810;
pub const VMCS_GUEST_IDTR_BASE: u32 = 0x00006818;
pub const VMCS_GUEST_IDTR_LIMIT: u32 = 0x00004812;

pub const VMCS_CTRL_PIN_BASED: u32 = 0x00004000;
pub const VMCS_CTRL_PROC_BASED: u32 = 0x00004002;
pub const VMCS_CTRL_PROC_BASED2: u32 = 0x0000401E;
pub const VMCS_CTRL_EXCEPTION_BITMAP: u32 = 0x00004004;

pub const VMCS_CTRL_EPTP: u32 = 0x0000201A;
pub const VMCS_HOST_CR0: u32 = 0x00006C00;
pub const VMCS_HOST_CR3: u32 = 0x00006C02;
pub const VMCS_HOST_CR4: u32 = 0x00006C04;
pub const VMCS_HOST_RSP: u32 = 0x00006C14;
pub const VMCS_HOST_RIP: u32 = 0x00006C16;

// VMX exit reasons
pub const EXIT_REASON_EXCEPTION_NMI: u32 = 0;
pub const EXIT_REASON_EXTERNAL_INTERRUPT: u32 = 1;
pub const EXIT_REASON_TRIPLE_FAULT: u32 = 2;
pub const EXIT_REASON_CPUID: u32 = 10;
pub const EXIT_REASON_HLT: u32 = 12;
pub const EXIT_REASON_VMCALL: u32 = 18;
pub const EXIT_REASON_IO_INSTRUCTION: u32 = 30;
pub const EXIT_REASON_MSR_READ: u32 = 31;
pub const EXIT_REASON_MSR_WRITE: u32 = 32;
pub const EXIT_REASON_EPT_VIOLATION: u32 = 48;
pub const EXIT_REASON_EPT_MISCONFIG: u32 = 49;


/// Guest CPU register state for x86_64
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GuestRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl GuestRegs {
    pub fn new() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rsp: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x2, // Reserved bit must be 1
        }
    }
}

/// Guest system registers (control and segment registers)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GuestSysRegs {
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub gdtr_base: u64,
    pub gdtr_limit: u32,
    pub idtr_base: u64,
    pub idtr_limit: u32,
    pub cs: SegmentDescriptor,
    pub ds: SegmentDescriptor,
    pub es: SegmentDescriptor,
    pub fs: SegmentDescriptor,
    pub gs: SegmentDescriptor,
    pub ss: SegmentDescriptor,
    pub tr: SegmentDescriptor,
    pub ldt: SegmentDescriptor,
}

impl GuestSysRegs {
    pub fn new() -> Self {
        Self {
            cr0: 0x60000010, // ET, NE bits set
            cr2: 0,
            cr3: 0,
            cr4: 0,
            cr8: 0,
            efer: 0,
            gdtr_base: 0,
            gdtr_limit: 0,
            idtr_base: 0,
            idtr_limit: 0,
            cs: SegmentDescriptor::new_code(),
            ds: SegmentDescriptor::new_data(),
            es: SegmentDescriptor::new_data(),
            fs: SegmentDescriptor::new_data(),
            gs: SegmentDescriptor::new_data(),
            ss: SegmentDescriptor::new_data(),
            tr: SegmentDescriptor::new_tss(),
            ldt: SegmentDescriptor::new(),
        }
    }
}

/// Segment descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SegmentDescriptor {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub access_rights: u32,
}

impl SegmentDescriptor {
    pub fn new() -> Self {
        Self {
            selector: 0,
            base: 0,
            limit: 0,
            access_rights: 0x10000, // Unusable
        }
    }
    
    pub fn new_code() -> Self {
        Self {
            selector: 0x08,
            base: 0,
            limit: 0xFFFFFFFF,
            access_rights: 0xC09B, // Present, code, executable, readable
        }
    }
    
    pub fn new_data() -> Self {
        Self {
            selector: 0x10,
            base: 0,
            limit: 0xFFFFFFFF,
            access_rights: 0xC093, // Present, data, writable
        }
    }
    
    pub fn new_tss() -> Self {
        Self {
            selector: 0x18,
            base: 0,
            limit: 0x67,
            access_rights: 0x008B, // Present, TSS
        }
    }
}

/// EPT page table entry (Intel SDM Vol 3, 28.2.2)
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct EptPte(pub u64);

impl EptPte {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const EXECUTE: u64 = 1 << 2;
    pub const MEMORY_TYPE_WB: u64 = 6 << 3; // Write-back
    pub const IGNORE_PAT: u64 = 1 << 6;
    pub const LARGE_PAGE: u64 = 1 << 7;
    pub const ACCESSED: u64 = 1 << 8;
    pub const DIRTY: u64 = 1 << 9;
    
    pub fn new() -> Self {
        Self(0)
    }
    
    pub fn is_present(&self) -> bool {
        (self.0 & (Self::READ | Self::WRITE | Self::EXECUTE)) != 0
    }
    
    pub fn addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }
    
    pub fn set_addr(&mut self, addr: u64) {
        self.0 = (self.0 & 0xFFF) | (addr & 0x000F_FFFF_FFFF_F000);
    }
}

/// EPT configuration
pub const EPT_PML4_SHIFT: usize = 39;
pub const EPT_PDPT_SHIFT: usize = 30;
pub const EPT_PD_SHIFT: usize = 21;
pub const EPT_PT_SHIFT: usize = 12;
pub const EPT_PTRS_PER_TABLE: usize = 512;

/// VM exit reasons
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Unknown = 0,
    Mmio = 1,
    Hlt = 2,
    Shutdown = 3,
    InternalError = 4,
    IoIn = 5,
    IoOut = 6,
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

/// I/O port access information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoAccess {
    pub port: u16,
    pub size: u8,
    pub direction: u8, // 0=out, 1=in
    pub data: u32,
}

impl IoAccess {
    pub fn new() -> Self {
        Self {
            port: 0,
            size: 0,
            direction: 0,
            data: 0,
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
    pub io: IoAccess,
    pub internal_error: InternalError,
}

impl RunState {
    pub fn new() -> Self {
        Self {
            exit_reason: ExitReason::Unknown as u32,
            _padding: 0,
            mmio: MmioAccess::new(),
            io: IoAccess::new(),
            internal_error: InternalError {
                error_code: 0,
                _padding: 0,
            },
        }
    }
}

// Safety: All fields are POD types
unsafe impl FromBytes for KvmCpuRegs {}
unsafe impl AsBytes for KvmCpuRegs {}

unsafe impl FromBytes for SegmentDescriptor {}
unsafe impl AsBytes for SegmentDescriptor {}

unsafe impl FromBytes for KvmSysRegs {}
unsafe impl AsBytes for KvmSysRegs {}

unsafe impl FromBytes for MmioAccess {}
unsafe impl AsBytes for MmioAccess {}

unsafe impl FromBytes for IoAccess {}
unsafe impl AsBytes for IoAccess {}

unsafe impl FromBytes for InternalError {}
unsafe impl AsBytes for InternalError {}

unsafe impl FromBytes for RunState {}
unsafe impl AsBytes for RunState {}