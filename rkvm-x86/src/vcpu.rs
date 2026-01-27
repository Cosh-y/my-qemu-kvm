//! Virtual CPU management for x86_64

use crate::types::*;
use crate::vmx::*;
use crate::ept::EptPageTable;
use kernel::prelude::*;

/// Virtual CPU structure
pub struct X86Vcpu {
    /// VMCS physical address
    vmcs_phys: u64,
    regs: GuestRegs,
    ept: *mut EptPageTable,
    initialized: bool,
}

impl X86Vcpu {
    /// Create new VCPU
    pub fn new(ept: &mut EptPageTable) -> Result<Self> {        
        // Allocate VMCS
        let vmcs_phys = alloc_vmcs()?;
        
        pr_info!("VCPU: Created with VMCS at 0x{:x}\n", vmcs_phys);
        
        Ok(Self {
            vmcs_phys,
            regs: GuestRegs::default(),
            ept: ept as *mut EptPageTable,
            initialized: false,
        })
    }
    
    /// Initialize VCPU (enter VMX operation)
    pub fn init(&mut self) -> Result<()> {
        unsafe {            
            // Clear VMCS
            vmclear(self.vmcs_phys)?;
            
            // Load VMCS
            vmptrld(self.vmcs_phys)?;
            
            // Setup initial VMCS state
            self.setup_vmcs()?;
        }
        
        pr_info!("VCPU: Initialized successfully\n");
        
        self.initialized = true;
        Ok(())
    }
    
    /// Setup VMCS with initial guest state
    unsafe fn setup_vmcs(&self) -> Result<()> {
        // Pin-based VM-execution controls
        // Adjust for reserved bits according to IA32_VMX_PINBASED_CTLS
        let pin_ctls = adjust_pin_based_controls(0);
        vmwrite(VMCS_PIN_BASED_VM_EXEC_CONTROL, pin_ctls as u64)?;
        
        // Primary processor-based VM-execution controls
        // Adjust for reserved bits according to IA32_VMX_PROCBASED_CTLS
        let mut proc_ctls = 0u32;
        proc_ctls |= CPU_BASED_HLT_EXITING;
        proc_ctls |= CPU_BASED_USE_MSR_BITMAPS;
        proc_ctls |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
        let proc_ctls = adjust_cpu_based_controls(proc_ctls);
        vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, proc_ctls as u64)?;
        
        // Secondary processor-based VM-execution controls
        // Adjust for reserved bits according to IA32_VMX_PROCBASED_CTLS2
        let mut proc_ctls2 = 0u32;
        proc_ctls2 |= SECONDARY_EXEC_ENABLE_EPT;
        proc_ctls2 |= SECONDARY_EXEC_UNRESTRICTED_GUEST;
        let proc_ctls2 = adjust_secondary_controls(proc_ctls2);
        vmwrite(VMCS_SECONDARY_VM_EXEC_CONTROL, proc_ctls2 as u64)?;
        
        // VM-exit controls
        // Adjust for reserved bits according to IA32_VMX_EXIT_CTLS
        let mut exit_ctls = 0u32;
        exit_ctls |= VM_EXIT_HOST_ADDR_SPACE_SIZE; // 64-bit host
        let exit_ctls = adjust_exit_controls(exit_ctls);
        vmwrite(VMCS_VM_EXIT_CONTROLS, exit_ctls as u64)?;
        
        // VM-entry controls
        // Adjust for reserved bits according to IA32_VMX_ENTRY_CTLS
        let entry_ctls = adjust_entry_controls(0);
        vmwrite(VMCS_VM_ENTRY_CONTROLS, entry_ctls as u64)?;
        
        // EPT pointer
        let eptp = (*self.ept).eptp();
        vmwrite(VMCS_EPT_POINTER, eptp)?;
        
        // Guest state - initialize to reset state
        vmwrite(VMCS_GUEST_CR0, 0x60000010)?; // CR0: PE=0, PG=0
        vmwrite(VMCS_GUEST_CR3, 0)?;
        vmwrite(VMCS_GUEST_CR4, 0)?;
        
        vmwrite(VMCS_GUEST_RIP, 0)?;
        vmwrite(VMCS_GUEST_RFLAGS, 0x2)?; // RFLAGS: bit 1 always 1
        
        // Segment registers (real mode)
        vmwrite(VMCS_GUEST_CS_SELECTOR, 0)?;
        vmwrite(VMCS_GUEST_CS_BASE, 0)?;
        vmwrite(VMCS_GUEST_CS_LIMIT, 0xFFFF)?;
        vmwrite(VMCS_GUEST_CS_AR_BYTES, 0x9B)?; // Code, read/execute
        
        // Host state
        vmwrite(VMCS_HOST_CR0, read_cr0())?;
        vmwrite(VMCS_HOST_CR3, read_cr3())?;
        vmwrite(VMCS_HOST_CR4, read_cr4())?;
        
        Ok(())
    }
    
    /// Run VCPU
    pub fn run(&mut self) -> Result<VmExitInfo> {
        if !self.initialized {
            self.init()?;
        }
        unsafe {
            // Load guest registers
            // TODO: Implement register loading
            
            // Launch or resume guest
            let result = self.vmlaunch_or_vmresume();
            
            if let Err(e) = result {
                let error = vmread(VMCS_VM_INSTRUCTION_ERROR)?;
                pr_err!("VM entry failed: error code {}\n", error);
                return Err(e);
            }
            
            // VM exit occurred - read exit info
            let exit_reason = vmread(VMCS_VM_EXIT_REASON)? as u32;
            let exit_qualification = vmread(VMCS_EXIT_QUALIFICATION)?;
            
            Ok(VmExitInfo {
                reason: exit_reason,
                qualification: exit_qualification,
                guest_rip: vmread(VMCS_GUEST_RIP)?,
                guest_rflags: vmread(VMCS_GUEST_RFLAGS)?,
            })
        }
    }
    
    /// Execute VMLAUNCH or VMRESUME
    unsafe fn vmlaunch_or_vmresume(&self) -> Result<()> {
        // Try VMRESUME first (for subsequent runs)
        let mut rflags: u64;
        core::arch::asm!(
            "vmresume",
            "pushfq",
            "pop {}",
            out(reg) rflags,
            options(nostack)
        );
        
        // If VMRESUME fails with VMfailInvalid, try VMLAUNCH
        if (rflags & 1) != 0 {
            core::arch::asm!(
                "vmlaunch",
                "pushfq",
                "pop {}",
                out(reg) rflags,
                options(nostack)
            );
            
            if (rflags & 1) != 0 {
                return Err(EINVAL);
            }
            if (rflags & (1 << 6)) != 0 {
                return Err(EIO);
            }
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
        // TODO: Write to VMCS
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

/// VM exit information
#[derive(Debug, Clone, Copy)]
pub struct VmExitInfo {
    pub reason: u32,
    pub qualification: u64,
    pub guest_rip: u64,
    pub guest_rflags: u64,
}

// Helper functions to read control registers
#[inline]
unsafe fn read_cr0() -> u64 {
    let value: u64;
    core::arch::asm!("mov {}, cr0", out(reg) value, options(nomem, nostack));
    value
}

#[inline]
unsafe fn read_cr3() -> u64 {
    let value: u64;
    core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack));
    value
}

#[inline]
unsafe fn read_cr4() -> u64 {
    let value: u64;
    core::arch::asm!("mov {}, cr4", out(reg) value, options(nomem, nostack));
    value
}

// 定义一个辅助结构体，包含所有需要的段信息
struct Segment {
    selector: u16,
    base: u64,
    limit: u32,
    ar: u32, // Access Rights
}

impl Segment {
    // 构造一个标准的实模式数据段
    fn real_mode_data(selector: u16) -> Self {
        Self {
            selector,
            base: (selector as u64) << 4,
            limit: 0xFFFF,
            ar: 0x93, // Present, Ring0, Data, Read/Write, Accessed
        }
    }

    // 构造一个标准的实模式代码段
    fn real_mode_code(selector: u16) -> Self {
        Self {
            selector,
            base: (selector as u64) << 4,
            limit: 0xFFFF,
            ar: 0x9B, // Present, Ring0, Code, Exec/Read, Accessed
        }
    }
}

// 在你的 setup_vmcs 函数中：
unsafe fn setup_segments(&self) -> Result<()> {
    // 1. 准备数据
    let cs = Segment::real_mode_code(0x0000);
    let ds = Segment::real_mode_data(0x0000); // 假设你让 DS=CS
    let tr_ar = 0x8B; // 32-bit TSS (Busy) - 必须是这个值

    // 2. 写入 CS
    vmwrite(VMCS_GUEST_CS_SELECTOR, cs.selector as u64)?;
    vmwrite(VMCS_GUEST_CS_BASE, cs.base)?;
    vmwrite(VMCS_GUEST_CS_LIMIT, cs.limit as u64)?;
    vmwrite(VMCS_GUEST_CS_AR_BYTES, cs.ar as u64)?;

    // 3. 循环写入 DS, ES, SS (它们通常配置一样)
    let data_segs = [
        (VMCS_GUEST_DS_SELECTOR, VMCS_GUEST_DS_BASE, VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_AR_BYTES),
        (VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_ES_BASE, VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_AR_BYTES),
        (VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_SS_BASE, VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_AR_BYTES),
    ];

    for (sel_field, base_field, lim_field, ar_field) in data_segs.iter() {
        vmwrite(*sel_field, ds.selector as u64)?;
        vmwrite(*base_field, ds.base)?;
        vmwrite(*lim_field, ds.limit as u64)?;
        vmwrite(*ar_field, ds.ar as u64)?;
    }
    
    // 4. 设置 FS, GS, LDTR 为 Unusable (偷懒区)
    // Bit 16 = 1 (Unusable)
    vmwrite(VMCS_GUEST_FS_AR_BYTES, 0x10000)?; 
    vmwrite(VMCS_GUEST_GS_AR_BYTES, 0x10000)?; 
    vmwrite(VMCS_GUEST_LDTR_AR_BYTES, 0x10000)?;

    // 5. 设置 TR (必须有效！)
    vmwrite(VMCS_GUEST_TR_SELECTOR, 0)?;
    vmwrite(VMCS_GUEST_TR_BASE, 0)?;
    vmwrite(VMCS_GUEST_TR_LIMIT, 0xFFFF)?;
    vmwrite(VMCS_GUEST_TR_AR_BYTES, tr_ar)?; 

    Ok(())
}