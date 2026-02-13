#![allow(missing_docs)]

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
// #[repr(C)]
// #[derive(Debug, Clone, Copy)]
// pub struct GuestSysRegs {
//     pub cr0: u64,
//     pub cr2: u64,
//     pub cr3: u64,
//     pub cr4: u64,
//     pub cr8: u64,
//     pub efer: u64,
//     pub gdtr_base: u64,
//     pub gdtr_limit: u32,
//     pub idtr_base: u64,
//     pub idtr_limit: u32,
//     pub cs: SegmentDescriptor,
//     pub ds: SegmentDescriptor,
//     pub es: SegmentDescriptor,
//     pub fs: SegmentDescriptor,
//     pub gs: SegmentDescriptor,
//     pub ss: SegmentDescriptor,
//     pub tr: SegmentDescriptor,
//     pub ldt: SegmentDescriptor,
// }

// impl GuestSysRegs {
//     pub fn new() -> Self {
//         Self {
//             cr0: 0x60000010, // ET, NE bits set
//             cr2: 0,
//             cr3: 0,
//             cr4: 0,
//             cr8: 0,
//             efer: 0,
//             gdtr_base: 0,
//             gdtr_limit: 0,
//             idtr_base: 0,
//             idtr_limit: 0,
//             cs: SegmentDescriptor::new_code(),
//             ds: SegmentDescriptor::new_data(),
//             es: SegmentDescriptor::new_data(),
//             fs: SegmentDescriptor::new_data(),
//             gs: SegmentDescriptor::new_data(),
//             ss: SegmentDescriptor::new_data(),
//             tr: SegmentDescriptor::new_tss(),
//             ldt: SegmentDescriptor::new(),
//         }
//     }
// }

macro_rules! save_regs_to_stack {
    () => {
        "
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rbp
        sub rsp, 8
        push rbx
        push rdx
        push rcx
        push rax"
    };
}

macro_rules! restore_regs_from_stack {
    () => {
        "
        pop rax
        pop rcx
        pop rdx
        pop rbx
        add rsp, 8
        pop rbp
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15"
    };
}
