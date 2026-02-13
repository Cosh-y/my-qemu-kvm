//! x86_64 register and control structures
//! This module provides functions to access x86 registers and hardcoded register bit structures
#![allow(missing_docs)]

// ============================================================================
// Control Register Functions
// ============================================================================

/// Read CR0 control register
#[inline]
pub unsafe fn read_cr0() -> u64 {
    let value: u64;
    unsafe { core::arch::asm!("mov {}, cr0", out(reg) value, options(nomem, nostack)); }
    value
}

/// Read CR3 control register
#[inline]
pub unsafe fn read_cr3() -> u64 {
    let value: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack)); }
    value
}

/// Read CR4 control register
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let value: u64;
    unsafe { core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack)); }
    value
}

// ============================================================================
// CR0 Flags
// ============================================================================

/// CR0 control register flags
#[derive(Debug, Clone, Copy)]
pub struct Cr0Flags(u64);

#[allow(dead_code)]
impl Cr0Flags {
    pub(crate) const PROTECTED_MODE_ENABLE: Self = Self(1 << 0);
    pub(crate) const MONITOR_COPROCESSOR: Self = Self(1 << 1);
    pub(crate) const EMULATE_COPROCESSOR: Self = Self(1 << 2);
    pub(crate) const TASK_SWITCHED: Self = Self(1 << 3);
    pub(crate) const EXTENSION_TYPE: Self = Self(1 << 4);
    pub(crate) const NUMERIC_ERROR: Self = Self(1 << 5);
    pub(crate) const WRITE_PROTECT: Self = Self(1 << 16);
    pub(crate) const ALIGNMENT_MASK: Self = Self(1 << 18);
    pub(crate) const NOT_WRITE_THROUGH: Self = Self(1 << 29);
    pub(crate) const CACHE_DISABLE: Self = Self(1 << 30);
    pub(crate) const PAGING: Self = Self(1 << 31);

    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl core::ops::BitOr for Cr0Flags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ============================================================================
// CR4 Flags
// ============================================================================

/// CR4 control register flags
#[derive(Debug, Clone, Copy)]
pub struct Cr4Flags(u64);

impl Cr4Flags {
    pub(crate) const VIRTUAL_8086_MODE_EXTENSIONS: Self = Self(1 << 0);
    pub(crate) const PROTECTED_MODE_VIRTUAL_INTERRUPTS: Self = Self(1 << 1);
    pub(crate) const TIME_STAMP_DISABLE: Self = Self(1 << 2);
    pub(crate) const DEBUGGING_EXTENSIONS: Self = Self(1 << 3);
    pub(crate) const PAGE_SIZE_EXTENSION: Self = Self(1 << 4);
    pub(crate) const PHYSICAL_ADDRESS_EXTENSION: Self = Self(1 << 5);
    pub(crate) const MACHINE_CHECK_EXCEPTION: Self = Self(1 << 6);
    pub(crate) const PAGE_GLOBAL_ENABLE: Self = Self(1 << 7);
    pub(crate) const PERFORMANCE_MONITORING_COUNTER_ENABLE: Self = Self(1 << 8);
    pub(crate) const OSFXSR: Self = Self(1 << 9);
    pub(crate) const OSXMMEXCPT_ENABLE: Self = Self(1 << 10);
    pub(crate) const USERMODE_INSTRUCTION_PREVENTION: Self = Self(1 << 11);
    pub(crate) const VIRTUAL_MACHINE_EXTENSIONS_ENABLE: Self = Self(1 << 13);
    pub(crate) const SAFER_MODE_EXTENSIONS_ENABLE: Self = Self(1 << 14);
    pub(crate) const FSGSBASE_ENABLE: Self = Self(1 << 16);
    pub(crate) const PCID_ENABLE: Self = Self(1 << 17);
    pub(crate) const XSAVE_ENABLE_BIT: Self = Self(1 << 18);
    pub(crate) const SUPERVISOR_MODE_EXECUTION_PROTECTION_ENABLE: Self = Self(1 << 20);
    pub(crate) const SUPERVISOR_MODE_ACCESS_PREVENTION_ENABLE: Self = Self(1 << 21);
    pub(crate) const PROTECTION_KEY_ENABLE: Self = Self(1 << 22);

    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl core::ops::BitOr for Cr4Flags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ============================================================================
// Segment Selectors
// ============================================================================

/// Segment selector
#[derive(Debug, Clone, Copy)]
pub struct SegmentSelector(u16);

impl SegmentSelector {
    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn index(self) -> u16 {
        self.0 >> 3
    }
}

/// Read ES segment selector
#[inline]
pub fn read_es() -> SegmentSelector {
    let value: u16;
    unsafe {
        core::arch::asm!("mov {:x}, es", out(reg) value, options(nomem, nostack));
    }
    SegmentSelector(value)
}

/// Read CS segment selector
#[inline]
pub fn read_cs() -> SegmentSelector {
    let value: u16;
    unsafe {
        core::arch::asm!("mov {:x}, cs", out(reg) value, options(nomem, nostack));
    }
    SegmentSelector(value)
}

/// Read SS segment selector
#[inline]
pub fn read_ss() -> SegmentSelector {
    let value: u16;
    unsafe {
        core::arch::asm!("mov {:x}, ss", out(reg) value, options(nomem, nostack));
    }
    SegmentSelector(value)
}

/// Read DS segment selector
#[inline]
pub fn read_ds() -> SegmentSelector {
    let value: u16;
    unsafe {
        core::arch::asm!("mov {:x}, ds", out(reg) value, options(nomem, nostack));
    }
    SegmentSelector(value)
}

/// Read FS segment selector
#[inline]
pub fn read_fs() -> SegmentSelector {
    let value: u16;
    unsafe {
        core::arch::asm!("mov {:x}, fs", out(reg) value, options(nomem, nostack));
    }
    SegmentSelector(value)
}

/// Read GS segment selector
#[inline]
pub fn read_gs() -> SegmentSelector {
    let value: u16;
    unsafe {
        core::arch::asm!("mov {:x}, gs", out(reg) value, options(nomem, nostack));
    }
    SegmentSelector(value)
}

/// Read TR (Task Register) segment selector
#[inline]
pub unsafe fn read_tr() -> SegmentSelector {
    let value: u16;
    unsafe { core::arch::asm!("str {:x}", out(reg) value, options(nomem, nostack)); }
    SegmentSelector(value)
}

// ============================================================================
// Descriptor Table Pointer
// ============================================================================

/// Descriptor table pointer (for GDTR/IDTR)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

/// Read GDTR (Global Descriptor Table Register)
#[inline]
pub unsafe fn read_gdtr(dest: &mut DescriptorTablePointer) {
    unsafe { core::arch::asm!("sgdt [{}]", in(reg) dest, options(nostack)); }
}

/// Read IDTR (Interrupt Descriptor Table Register)
#[inline]
pub unsafe fn read_idtr(dest: &mut DescriptorTablePointer) {
    unsafe { core::arch::asm!("sidt [{}]", in(reg) dest, options(nostack)); }
}

// ============================================================================
// VMX Control Flags
// ============================================================================

/// Pin-based VM-execution controls
#[derive(Debug, Clone, Copy)]
pub struct PinbasedControls(u32);

impl PinbasedControls {
    pub(crate) const EXTERNAL_INTERRUPT_EXITING: Self = Self(1 << 0);
    pub(crate) const NMI_EXITING: Self = Self(1 << 3);
    pub(crate) const VIRTUAL_NMIS: Self = Self(1 << 5);
    pub(crate) const ACTIVATE_VMX_PREEMPTION_TIMER: Self = Self(1 << 6);
    pub(crate) const PROCESS_POSTED_INTERRUPTS: Self = Self(1 << 7);

    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Primary processor-based VM-execution controls
#[derive(Debug, Clone, Copy)]
pub struct PrimaryControls(u32);

impl PrimaryControls {
    pub(crate) const INTERRUPT_WINDOW_EXITING: Self = Self(1 << 2);
    pub(crate) const USE_TSC_OFFSETTING: Self = Self(1 << 3);
    pub(crate) const HLT_EXITING: Self = Self(1 << 7);
    pub(crate) const INVLPG_EXITING: Self = Self(1 << 9);
    pub(crate) const MWAIT_EXITING: Self = Self(1 << 10);
    pub(crate) const RDPMC_EXITING: Self = Self(1 << 11);
    pub(crate) const RDTSC_EXITING: Self = Self(1 << 12);
    pub(crate) const CR3_LOAD_EXITING: Self = Self(1 << 15);
    pub(crate) const CR3_STORE_EXITING: Self = Self(1 << 16);
    pub(crate) const CR8_LOAD_EXITING: Self = Self(1 << 19);
    pub(crate) const CR8_STORE_EXITING: Self = Self(1 << 20);
    pub(crate) const USE_TPR_SHADOW: Self = Self(1 << 21);
    pub(crate) const NMI_WINDOW_EXITING: Self = Self(1 << 22);
    pub(crate) const MOV_DR_EXITING: Self = Self(1 << 23);
    pub(crate) const UNCONDITIONAL_IO_EXITING: Self = Self(1 << 24);
    pub(crate) const USE_IO_BITMAPS: Self = Self(1 << 25);
    pub(crate) const MONITOR_TRAP_FLAG: Self = Self(1 << 27);
    pub(crate) const USE_MSR_BITMAPS: Self = Self(1 << 28);
    pub(crate) const MONITOR_EXITING: Self = Self(1 << 29);
    pub(crate) const PAUSE_EXITING: Self = Self(1 << 30);
    pub(crate) const SECONDARY_CONTROLS: Self = Self(1 << 31);

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for PrimaryControls {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Secondary processor-based VM-execution controls
#[derive(Debug, Clone, Copy)]
pub struct SecondaryControls(u32);

impl SecondaryControls {
    pub(crate) const VIRTUALIZE_APIC_ACCESSES: Self = Self(1 << 0);
    pub(crate) const ENABLE_EPT: Self = Self(1 << 1);
    pub(crate) const DESCRIPTOR_TABLE_EXITING: Self = Self(1 << 2);
    pub(crate) const ENABLE_RDTSCP: Self = Self(1 << 3);
    pub(crate) const VIRTUALIZE_X2APIC_MODE: Self = Self(1 << 4);
    pub(crate) const ENABLE_VPID: Self = Self(1 << 5);
    pub(crate) const WBINVD_EXITING: Self = Self(1 << 6);
    pub(crate) const UNRESTRICTED_GUEST: Self = Self(1 << 7);
    pub(crate) const APIC_REGISTER_VIRTUALIZATION: Self = Self(1 << 8);
    pub(crate) const VIRTUAL_INTERRUPT_DELIVERY: Self = Self(1 << 9);
    pub(crate) const PAUSE_LOOP_EXITING: Self = Self(1 << 10);
    pub(crate) const RDRAND_EXITING: Self = Self(1 << 11);
    pub(crate) const ENABLE_INVPCID: Self = Self(1 << 12);
    pub(crate) const ENABLE_VM_FUNCTIONS: Self = Self(1 << 13);
    pub(crate) const VMCS_SHADOWING: Self = Self(1 << 14);
    pub(crate) const ENABLE_ENCLS_EXITING: Self = Self(1 << 15);
    pub(crate) const RDSEED_EXITING: Self = Self(1 << 16);
    pub(crate) const ENABLE_PML: Self = Self(1 << 17);
    pub(crate) const EPT_VIOLATION_VE: Self = Self(1 << 18);
    pub(crate) const CONCEAL_VMX_FROM_PT: Self = Self(1 << 19);
    pub(crate) const ENABLE_XSAVES_XRSTORS: Self = Self(1 << 20);

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for SecondaryControls {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// VM-exit controls
#[derive(Debug, Clone, Copy)]
pub struct ExitControls(u32);

impl ExitControls {
    pub(crate) const SAVE_DEBUG_CONTROLS: Self = Self(1 << 2);
    pub(crate) const HOST_ADDRESS_SPACE_SIZE: Self = Self(1 << 9);
    pub(crate) const LOAD_IA32_PERF_GLOBAL_CTRL: Self = Self(1 << 12);
    pub(crate) const ACKNOWLEDGE_INTERRUPT_ON_EXIT: Self = Self(1 << 15);
    pub(crate) const SAVE_IA32_PAT: Self = Self(1 << 18);
    pub(crate) const LOAD_IA32_PAT: Self = Self(1 << 19);
    pub(crate) const SAVE_IA32_EFER: Self = Self(1 << 20);
    pub(crate) const LOAD_IA32_EFER: Self = Self(1 << 21);
    pub(crate) const SAVE_VMX_PREEMPTION_TIMER_VALUE: Self = Self(1 << 22);
    pub(crate) const CLEAR_IA32_BNDCFGS: Self = Self(1 << 23);
    pub(crate) const CONCEAL_VMX_FROM_PT: Self = Self(1 << 24);

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for ExitControls {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// VM-entry controls
#[derive(Debug, Clone, Copy)]
pub struct EntryControls(u32);

impl EntryControls {
    pub(crate) const LOAD_DEBUG_CONTROLS: Self = Self(1 << 2);
    pub(crate) const IA32E_MODE_GUEST: Self = Self(1 << 9);
    pub(crate) const ENTRY_TO_SMM: Self = Self(1 << 10);
    pub(crate) const DEACTIVATE_DUAL_MONITOR_TREATMENT: Self = Self(1 << 11);
    pub(crate) const LOAD_IA32_PERF_GLOBAL_CTRL: Self = Self(1 << 13);
    pub(crate) const LOAD_IA32_PAT: Self = Self(1 << 14);
    pub(crate) const LOAD_IA32_EFER: Self = Self(1 << 15);
    pub(crate) const LOAD_IA32_BNDCFGS: Self = Self(1 << 16);
    pub(crate) const CONCEAL_VMX_FROM_PT: Self = Self(1 << 17);

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl core::ops::BitOr for EntryControls {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
