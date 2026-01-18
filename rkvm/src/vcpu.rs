//! Virtual CPU implementation

use kernel::prelude::*;
use crate::types::*;
use crate::hvc;
use crate::wrap::*;

/// VCPU structure - must match C layout for assembly code
#[repr(C, align(512))]
pub struct RKvmVcpu {
    /// Guest register state - must be at offset 0
    pub regs: KvmCpuRegs,
    
    /// Padding to reach offset 512
    _pad1: [u8; 512 - core::mem::size_of::<KvmCpuRegs>()],
    
    /// Guest system registers - must be at offset 512
    pub sys_regs: KvmSysRegs,
    
    /// Padding to reach offset 1024
    _pad2: [u8; 1024 - 512 - core::mem::size_of::<KvmSysRegs>()],
    
    /// Stage-2 page table base (VTTBR_EL2) - offset 1024
    pub vttbr_el2: u64,
    
    /// HCR_EL2 configuration - offset 1032
    pub hcr_el2: u64,
    
    /// Exception information - saved on VM exit
    pub esr_el2: u64,
    pub far_el2: u64,
    pub hpfar_el2: u64,
    pub vtcr_el2: u64,
}

impl RKvmVcpu {
    /// Create a new VCPU
    pub fn new(s2_pgd_phys: PhysAddr, vmid: u64, vtcr: u64) -> Self {
        let mut vcpu = Self {
            regs: KvmCpuRegs::new(),
            _pad1: [0; 512 - core::mem::size_of::<KvmCpuRegs>()],
            sys_regs: KvmSysRegs::new(),
            _pad2: [0; 1024 - 512 - core::mem::size_of::<KvmSysRegs>()],
            vttbr_el2: 0,
            hcr_el2: HCR_GUEST_FLAGS,
            esr_el2: 0,
            far_el2: 0,
            hpfar_el2: 0,
            vtcr_el2: vtcr,
        };
        
        // Set up VTTBR_EL2 (stage-2 translation base + VMID)
        vcpu.vttbr_el2 = s2_pgd_phys | (vmid << 48);
        
        // Initialize guest entry point
        vcpu.regs.pc = 0x40000000;
        vcpu.regs.pstate = 0x3c5; // EL1h, IRQ/FIQ masked
        
        vcpu
    }
    
    /// Run the vCPU
    pub fn run(&mut self) -> Result<RunState> {
        // Get physical address of vcpu structure
        let vcpu_vaddr = self as *const _ as VirtAddr;
        let vcpu_phys = virt_to_phys(vcpu_vaddr);
        
        // Call HVC to run guest
        let ret = hvc::vcpu_run(vcpu_phys)?;
        
        if ret != 0 {
            return Ok(RunState {
                exit_reason: ExitReason::InternalError as u32,
                _padding: 0,
                mmio: MmioAccess::new(),
                internal_error: InternalError {
                    error_code: ret as u32,
                    _padding: 0,
                },
            });
        }
        
        // Handle VM exit
        self.handle_exit()
    }
    
    /// Handle VM exit - analyze why guest exited
    fn handle_exit(&self) -> Result<RunState> {
        let esr_ec = (self.esr_el2 >> 26) & 0x3F;
        
        let mut run_state = RunState::new();
        
        match esr_ec {
            0x24 | 0x20 => {
                // Data/Instruction Abort from lower EL (Stage-2 fault)
                run_state.exit_reason = ExitReason::Mmio as u32;
                run_state.mmio.phys_addr = self.far_el2;
                run_state.mmio.len = 4;
                run_state.mmio.is_write = if esr_ec == 0x24 && (self.esr_el2 & (1 << 6)) != 0 { 1 } else { 0 };
                run_state.mmio.data = self.regs.x[1];
            }
            0x01 => {
                // WFI/WFE instruction
                run_state.exit_reason = ExitReason::Hlt as u32;
            }
            _ => {
                run_state.exit_reason = ExitReason::Unknown as u32;
            }
        }
        
        Ok(run_state)
    }
}
