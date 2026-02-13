//! Core data structures for x86_64 KVM implementation
//! 
//! This module defines VMX and EPT related structures for Intel VT-x

#![allow(missing_docs)]

/// Physical address type
pub type PhysAddr = u64;

/// Virtual address type
pub type VirtAddr = usize;

/// Guest physical address type
pub type GuestPhysAddr = u64;

/// Memory size type
pub type MemSize = usize;

// VMCS field encodings (Intel SDM Vol 3, Appendix B)
// pub const VMCS_GUEST_ES_SELECTOR: u32 = 0x00000800;
// pub const VMCS_GUEST_CS_SELECTOR: u32 = 0x00000802;
// pub const VMCS_GUEST_SS_SELECTOR: u32 = 0x00000804;
// pub const VMCS_GUEST_DS_SELECTOR: u32 = 0x00000806;
// pub const VMCS_GUEST_FS_SELECTOR: u32 = 0x00000808;
// pub const VMCS_GUEST_GS_SELECTOR: u32 = 0x0000080A;
// pub const VMCS_GUEST_LDTR_SELECTOR: u32 = 0x0000080C;
// pub const VMCS_GUEST_TR_SELECTOR: u32 = 0x0000080E;

// pub const VMCS_GUEST_CR0: u32 = 0x00006800;
// pub const VMCS_GUEST_CR3: u32 = 0x00006802;
// pub const VMCS_GUEST_CR4: u32 = 0x00006804;
// pub const VMCS_GUEST_DR7: u32 = 0x0000681A;
// pub const VMCS_GUEST_RSP: u32 = 0x0000681C;
// pub const VMCS_GUEST_RIP: u32 = 0x0000681E;
// pub const VMCS_GUEST_RFLAGS: u32 = 0x00006820;

// pub const VMCS_GUEST_GDTR_BASE: u32 = 0x00006816;
// pub const VMCS_GUEST_GDTR_LIMIT: u32 = 0x00004810;
// pub const VMCS_GUEST_IDTR_BASE: u32 = 0x00006818;
// pub const VMCS_GUEST_IDTR_LIMIT: u32 = 0x00004812;

// pub const VMCS_CTRL_PIN_BASED: u32 = 0x00004000;
// pub const VMCS_CTRL_PROC_BASED: u32 = 0x00004002;
// pub const VMCS_CTRL_PROC_BASED2: u32 = 0x0000401E;
// pub const VMCS_CTRL_EXCEPTION_BITMAP: u32 = 0x00004004;

// pub const VMCS_CTRL_EPTP: u32 = 0x0000201A;
// pub const VMCS_HOST_CR0: u32 = 0x00006C00;
// pub const VMCS_HOST_CR3: u32 = 0x00006C02;
// pub const VMCS_HOST_CR4: u32 = 0x00006C04;
// pub const VMCS_HOST_RSP: u32 = 0x00006C14;
// pub const VMCS_HOST_RIP: u32 = 0x00006C16;

// // VMX exit reasons
// pub const EXIT_REASON_EXCEPTION_NMI: u32 = 0;
// pub const EXIT_REASON_EXTERNAL_INTERRUPT: u32 = 1;
// pub const EXIT_REASON_TRIPLE_FAULT: u32 = 2;
// pub const EXIT_REASON_CPUID: u32 = 10;
// pub const EXIT_REASON_HLT: u32 = 12;
// pub const EXIT_REASON_VMCALL: u32 = 18;
// pub const EXIT_REASON_IO_INSTRUCTION: u32 = 30;
// pub const EXIT_REASON_MSR_READ: u32 = 31;
// pub const EXIT_REASON_MSR_WRITE: u32 = 32;
// pub const EXIT_REASON_EPT_VIOLATION: u32 = 48;
// pub const EXIT_REASON_EPT_MISCONFIG: u32 = 49;

// Segment descriptor
// #[repr(C)]
// #[derive(Debug, Clone, Copy)]
// pub struct SegmentDescriptor {
//     pub selector: u16,
//     pub base: u64,
//     pub limit: u32,
//     pub access_rights: u32,
// }

// impl SegmentDescriptor {
//     pub fn new() -> Self {
//         Self {
//             selector: 0,
//             base: 0,
//             limit: 0,
//             access_rights: 0x10000, // Unusable
//         }
//     }
    
//     pub fn new_code() -> Self {
//         Self {
//             selector: 0x08,
//             base: 0,
//             limit: 0xFFFFFFFF,
//             access_rights: 0xC09B, // Present, code, executable, readable
//         }
//     }
    
//     pub fn new_data() -> Self {
//         Self {
//             selector: 0x10,
//             base: 0,
//             limit: 0xFFFFFFFF,
//             access_rights: 0xC093, // Present, data, writable
//         }
//     }
    
//     pub fn new_tss() -> Self {
//         Self {
//             selector: 0x18,
//             base: 0,
//             limit: 0x67,
//             access_rights: 0x008B, // Present, TSS
//         }
//     }
// }
