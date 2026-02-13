//! Virtual CPU management for x86_64
#![allow(missing_docs)]

use kernel::prelude::*;

use crate::types::*;
use crate::vmx::*;
use crate::pt::PML4_GPA;
use crate::regs::*;
use crate::x86::*;

/// Virtual CPU structure
pub struct X86Vcpu {
    /// VMCS physical address
    vmcs_phys: u64,
    regs: GuestRegs,
    entry: GuestPhysAddr,
    initialized: bool,
    launched: bool,
}

impl X86Vcpu {
    /// Create new VCPU
    pub fn new() -> Result<Self> {        
        // Allocate VMCS
        let vmcs_phys = alloc_vmcs()?;
        
        pr_info!("VCPU: Created with VMCS at 0x{:x}\n", vmcs_phys);
        
        Ok(Self {
            vmcs_phys,
            regs: GuestRegs::new(),
            entry: 0,
            initialized: false,
            launched: false,
        })
    }

    pub fn setup_entry(&mut self, entry: GuestPhysAddr) {
        self.entry = entry;
    }
    
    /// Initialize VCPU (enter VMX operation)
    pub fn init(&mut self, eptp: u64) -> Result<()> {
        unsafe {
            vmclear(self.vmcs_phys)?;
            vmptrld(self.vmcs_phys)?;
            
            self.setup_vmcs(eptp)?;
        }
        
        pr_info!("VCPU: Initialized successfully\n");
        
        self.initialized = true;
        self.launched = false;
        Ok(())
    }
    
    /// Setup VMCS with initial guest state
    fn setup_vmcs(&self, eptp: u64) -> Result<()> {
        self.setup_vmcs_host()?;
        self.setup_vmcs_guest()?;
        self.setup_vmcs_controls(eptp)?;
        Ok(())
    }

    fn setup_vmcs_host(&self) -> Result<()> {
        VmcsHost64::IA32_PAT.write(Msr::IA32_PAT.read())?;
        VmcsHost64::IA32_EFER.write(Msr::IA32_EFER.read())?;

        unsafe {
            VmcsHostNW::CR0.write(read_cr0() as _)?;
            VmcsHostNW::CR3.write(read_cr3() as _)?;
            VmcsHostNW::CR4.write(read_cr4() as _)?;
        }

        VmcsHost16::ES_SELECTOR.write(read_es().bits())?;
        VmcsHost16::CS_SELECTOR.write(read_cs().bits())?;
        VmcsHost16::SS_SELECTOR.write(read_ss().bits())?;
        VmcsHost16::DS_SELECTOR.write(read_ds().bits())?;
        VmcsHost16::FS_SELECTOR.write(read_fs().bits())?;
        VmcsHost16::GS_SELECTOR.write(read_gs().bits())?;
        VmcsHostNW::FS_BASE.write(Msr::IA32_FS_BASE.read() as _)?;
        VmcsHostNW::GS_BASE.write(Msr::IA32_GS_BASE.read() as _)?;

        let tr = unsafe { read_tr() };
        let mut gdtp = DescriptorTablePointer::default();
        let mut idtp = DescriptorTablePointer::default();
        unsafe {
            read_gdtr(&mut gdtp);
            read_idtr(&mut idtp);
        }
        VmcsHost16::TR_SELECTOR.write(tr.bits())?;
        VmcsHostNW::TR_BASE.write(get_tr_base(tr, &gdtp) as _)?;
        VmcsHostNW::GDTR_BASE.write(gdtp.base as _)?;
        VmcsHostNW::IDTR_BASE.write(idtp.base as _)?;
        VmcsHostNW::RIP.write(__rkvm_vm_exit_handler as _)?;

        VmcsHostNW::IA32_SYSENTER_ESP.write(0)?;
        VmcsHostNW::IA32_SYSENTER_EIP.write(0)?;
        VmcsHost32::IA32_SYSENTER_CS.write(0)?;
        Ok(())
    }

    fn setup_vmcs_guest(&self) -> Result<()> {
        let cr0_guest = Cr0Flags::PROTECTED_MODE_ENABLE
            | Cr0Flags::EXTENSION_TYPE
            | Cr0Flags::NUMERIC_ERROR
            | Cr0Flags::PAGING;
        let cr0_host_owned = Cr0Flags::NUMERIC_ERROR | Cr0Flags::NOT_WRITE_THROUGH | Cr0Flags::CACHE_DISABLE;
        let cr0_read_shadow = Cr0Flags::NUMERIC_ERROR;
        VmcsGuestNW::CR0.write((cr0_guest.bits()) as _)?;
        VmcsControlNW::CR0_GUEST_HOST_MASK.write((cr0_host_owned.bits()) as _)?;
        VmcsControlNW::CR0_READ_SHADOW.write((cr0_read_shadow.bits()) as _)?;

        // enable physical address extensions that required in IA-32e mode.
        let cr4_guest = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS_ENABLE;
        let cr4_host_owned = Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS_ENABLE;
        let cr4_read_shadow = 0;
        VmcsGuestNW::CR4.write(cr4_guest.bits() as _)?;
        VmcsControlNW::CR4_GUEST_HOST_MASK.write(cr4_host_owned.bits() as _)?;
        VmcsControlNW::CR4_READ_SHADOW.write(cr4_read_shadow)?;

        {
            use VmcsGuest16::*;
            use VmcsGuest32::*;
            use VmcsGuestNW::*;
            ES_SELECTOR.write(0)?;
            ES_BASE.write(0)?;
            ES_LIMIT.write(0xffff)?;
            ES_ACCESS_RIGHTS.write(0x93)?;

            CS_SELECTOR.write(0)?;
            CS_BASE.write(0)?;
            CS_LIMIT.write(0xffff)?;
            CS_ACCESS_RIGHTS.write(0x209b)?;

            SS_SELECTOR.write(0)?;
            SS_BASE.write(0)?;
            SS_LIMIT.write(0xffff)?;
            SS_ACCESS_RIGHTS.write(0x93)?;

            DS_SELECTOR.write(0)?;
            DS_BASE.write(0)?;
            DS_LIMIT.write(0xffff)?;
            DS_ACCESS_RIGHTS.write(0x93)?;

            FS_SELECTOR.write(0)?;
            FS_BASE.write(0)?;
            FS_LIMIT.write(0xffff)?;
            FS_ACCESS_RIGHTS.write(0x93)?;

            GS_SELECTOR.write(0)?;
            GS_BASE.write(0)?;
            GS_LIMIT.write(0xffff)?;
            GS_ACCESS_RIGHTS.write(0x93)?;

            TR_SELECTOR.write(0)?;
            TR_BASE.write(0)?;
            TR_LIMIT.write(0xffff)?;
            TR_ACCESS_RIGHTS.write(0x8b)?;

            LDTR_SELECTOR.write(0)?;
            LDTR_BASE.write(0)?;
            LDTR_LIMIT.write(0xffff)?;
            LDTR_ACCESS_RIGHTS.write(0x82)?;
        }

        VmcsGuestNW::GDTR_BASE.write(0)?;
        VmcsGuest32::GDTR_LIMIT.write(0xffff)?;
        VmcsGuestNW::IDTR_BASE.write(0)?;
        VmcsGuest32::IDTR_LIMIT.write(0xffff)?;

        VmcsGuestNW::CR3.write(unsafe { PML4_GPA as usize })?;  // guest page table base
        VmcsGuestNW::DR7.write(0x400)?;
        VmcsGuestNW::RSP.write(0)?; // guest code doesn't use stack
        VmcsGuestNW::RIP.write(self.entry as _)?;  // entry pc
        VmcsGuestNW::RFLAGS.write(0x2)?;
        VmcsGuestNW::PENDING_DBG_EXCEPTIONS.write(0)?;
        VmcsGuestNW::IA32_SYSENTER_ESP.write(0)?;
        VmcsGuestNW::IA32_SYSENTER_EIP.write(0)?;
        VmcsGuest32::IA32_SYSENTER_CS.write(0)?;

        VmcsGuest32::INTERRUPTIBILITY_STATE.write(0)?;
        VmcsGuest32::ACTIVITY_STATE.write(0)?;
        VmcsGuest32::VMX_PREEMPTION_TIMER_VALUE.write(0)?;

        VmcsGuest64::LINK_PTR.write(u64::MAX)?; // SDM Vol. 3C, Section 24.4.2
        VmcsGuest64::IA32_DEBUGCTL.write(0)?;
        VmcsGuest64::IA32_PAT.write(Msr::IA32_PAT.read())?;
        VmcsGuest64::IA32_EFER.write(Msr::IA32_EFER.read())?; // required in IA-32e mode
        Ok(())
    }

    fn setup_vmcs_controls(&self, eptp: u64) -> Result<()> {
        set_control(
            VmcsControl32::PINBASED_EXEC_CONTROLS,
            Msr::IA32_VMX_TRUE_PINBASED_CTLS,
            Msr::IA32_VMX_PINBASED_CTLS.read() as u32,
            PinbasedControls::NMI_EXITING.bits(),  // 此时时钟中断等 external interrupt 不会引起 VM exit
            0,
        )?;

        set_control(
            VmcsControl32::PRIMARY_PROCBASED_EXEC_CONTROLS,
            Msr::IA32_VMX_TRUE_PROCBASED_CTLS,
            Msr::IA32_VMX_PROCBASED_CTLS.read() as u32,
            PrimaryControls::SECONDARY_CONTROLS.bits(),
            (PrimaryControls::CR3_LOAD_EXITING | PrimaryControls::CR3_STORE_EXITING).bits(),
        )?;

        set_control(
            VmcsControl32::SECONDARY_PROCBASED_EXEC_CONTROLS,
            Msr::IA32_VMX_PROCBASED_CTLS2,
            0,
            (SecondaryControls::ENABLE_EPT | SecondaryControls::ENABLE_RDTSCP | SecondaryControls::ENABLE_INVPCID).bits(),
            0,
        )?;

        set_control(
            VmcsControl32::VMEXIT_CONTROLS,
            Msr::IA32_VMX_TRUE_EXIT_CTLS,
            Msr::IA32_VMX_EXIT_CTLS.read() as u32,
            (ExitControls::HOST_ADDRESS_SPACE_SIZE | ExitControls::SAVE_IA32_PAT | ExitControls::LOAD_IA32_PAT
             | ExitControls::SAVE_IA32_EFER | ExitControls::LOAD_IA32_EFER).bits(),
            0,
        )?;

        set_control(
            VmcsControl32::VMENTRY_CONTROLS,
            Msr::IA32_VMX_TRUE_ENTRY_CTLS,
            Msr::IA32_VMX_ENTRY_CTLS.read() as u32,
            (EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_PAT | EntryControls::LOAD_IA32_EFER).bits(),
            0,
        )?;

        // No MSR switches if hypervisor doesn't use and there is only one vCPU.
        VmcsControl32::VMEXIT_MSR_STORE_COUNT.write(0)?;
        VmcsControl32::VMEXIT_MSR_LOAD_COUNT.write(0)?;
        VmcsControl32::VMENTRY_MSR_LOAD_COUNT.write(0)?;

        // Pass-through exceptions, I/O instructions, and MSR read/write.
        VmcsControl32::EXCEPTION_BITMAP.write(0)?;
        VmcsControl64::IO_BITMAP_A_ADDR.write(0)?;
        VmcsControl64::IO_BITMAP_B_ADDR.write(0)?;
        VmcsControl64::MSR_BITMAPS_ADDR.write(0)?; // TODO

        // setup EPT
        VmcsControl64::EPTP.write(eptp)?;
        Ok(())
    }
    
    /// Run VCPU
    pub fn run(&mut self, eptp: u64) -> Result<VmxExitInfo> {
        if !self.initialized {
            self.init(eptp)?;
        }
        unsafe {
            // Load guest registers
            // TODO: Implement register loading
            
            // Launch or resume guest
            let _result = self.vmlaunch_or_vmresume()?;
            if !self.launched {
                 self.launched = true;
            }
            
            exit_info()
        }
    }
    
    /// Execute VMLAUNCH or VMRESUME
    unsafe fn vmlaunch_or_vmresume(&mut self) -> Result<()> {
        let launched = if self.launched { 1 } else { 0 };
        let ret = unsafe { __rkvm_vcpu_run(&mut self.regs, launched) };
        if ret != 0 {
            return Err(EIO);
        }
        Ok(())
    }
    
    /// Get guest registers
    pub fn get_regs(&self) -> &GuestRegs {
        &self.regs
    }
    
    /// Set guest registers
    pub fn set_regs(&mut self, regs: &GuestRegs) {
        self.regs = *regs;
    }
}

impl Drop for X86Vcpu {
    fn drop(&mut self) {
        unsafe {
            // Exit VMX operation
            let _ = vmxoff();
        }
    }
}

fn get_bits(value: u64, range: core::ops::Range<usize>) -> u64 {
    (value >> range.start) & ((1u64 << (range.end - range.start)) - 1)
}

fn get_tr_base(tr: SegmentSelector, gdt: &DescriptorTablePointer) -> u64 {
    let index = tr.index() as usize;
    let table_len = (gdt.limit as usize + 1) / core::mem::size_of::<u64>();
    let table = unsafe { core::slice::from_raw_parts(gdt.base as *const u64, table_len) };
    let entry = table[index];
    if entry & (1 << 47) != 0 {
        // present
        let base_low = get_bits(entry, 16..40) | get_bits(entry, 56..64) << 24;
        let base_high = table[index + 1] & 0xffff_ffff;
        base_low | base_high << 32
    } else {
        // no present
        0
    }
}

extern "C" {
    fn __rkvm_vcpu_run(regs_ptr: *mut GuestRegs, launched: u64) -> u64;
    fn __rkvm_vm_exit_handler();
}

core::arch::global_asm!(
    r#"
    .global __rkvm_vcpu_run
    .global __rkvm_vm_exit_handler
    
    # args: rdi = regs_ptr, rsi = launched (bool/u64)
    __rkvm_vcpu_run:
        # Save Callee-Saved Host Registers (according to System V AMD64 ABI)
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15

        # save guest regs pointer
        push rdi

        # Save Host RSP to VMCS
        # so that we can restore host regs after VM Exit
        # VMCS_HOST_RSP = 0x6C14
        mov rdx, 0x6C14
        vmwrite rdx, rsp
        jna .LaunchFail

        # save launched flag to stack
        push rsi

        # restore guest registers from GuestRegs struct
        mov rax, [rdi + 0x00]
        mov rbx, [rdi + 0x08]
        mov rcx, [rdi + 0x10]
        mov rdx, [rdi + 0x18]
        mov rsi, [rdi + 0x20]
        ## skip rdi, rsp
        mov rbp, [rdi + 0x38]
        mov r8,  [rdi + 0x40]
        mov r9,  [rdi + 0x48]
        mov r10, [rdi + 0x50]
        mov r11, [rdi + 0x58]
        mov r12, [rdi + 0x60]
        mov r13, [rdi + 0x68]
        mov r14, [rdi + 0x70]
        mov r15, [rdi + 0x78]
        mov rdi, [rdi + 0x28]  # restore rdi last
        
        # Check if we should VMLAUNCH or VMRESUME
        cmp qword ptr [rsp], 0
        jne .DoResume
        
    .DoLaunch:
        vmlaunch
        jmp .LaunchFail
        
    .DoResume:
        vmresume
        jmp .LaunchFail

    # This is where HOST_RIP should point
    __rkvm_vm_exit_handler:
        # restore guest regs struct pointer
        # after xchg [rsp] = guest rdi value; rdi = host rdi val = guest regs ptr
        xchg rdi, [rsp]

        # Save guest registers to GuestRegs struct
        mov [rdi + 0x00], rax
        mov [rdi + 0x08], rbx
        mov [rdi + 0x10], rcx
        mov [rdi + 0x18], rdx
        mov [rdi + 0x20], rsi
        ## skip rdi, rsp
        mov [rdi + 0x38], rbp
        mov [rdi + 0x40], r8
        mov [rdi + 0x48], r9
        mov [rdi + 0x50], r10
        mov [rdi + 0x58], r11
        mov [rdi + 0x60], r12
        mov [rdi + 0x68], r13
        mov [rdi + 0x70], r14
        mov [rdi + 0x78], r15

        pop rax  # get guest rdi value
        mov [rdi + 0x28], rax  # save guest rdi value
        
        # Restore Host Registers
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp

        # Return 0 (Success/Exit occurred)
        xor rax, rax
        ret

    .LaunchFail:
        # Failure path
        pop rax
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        
        # Return error code (just 1 for simplicity)
        mov rax, 1
        ret
    "#
);