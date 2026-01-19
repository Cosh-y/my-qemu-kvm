//! Virtual machine management

use kernel::prelude::*;
use kernel::bindings;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::types::*;
use crate::stage2::Stage2PageTable;
use crate::vcpu::RKvmVcpu;
use crate::wrap::*;

/// Global VMID allocator
static NEXT_VMID: AtomicU64 = AtomicU64::new(1);

/// Virtual machine structure
pub struct RKvmVm {
    /// Stage-2 page tables
    s2_pgtable: Stage2PageTable,
    
    /// Guest memory
    guest_mem: VirtAddr,
    guest_phys: PhysAddr,
    guest_mem_size: MemSize,
    
    /// VMID
    vmid: u64,
    
    /// VCPU (single vCPU for simplicity)
    vcpu: Option<KBox<RKvmVcpu>>,
    
    /// Created flag
    created: bool,
}

impl RKvmVm {
    /// Create a new VM
    pub fn new() -> Result<Self> {
        // Allocate guest memory (4MB, physically contiguous)
        let guest_mem_size: MemSize = 4 * 1024 * 1024;
        let guest_mem = kmalloc(guest_mem_size, bindings::GFP_KERNEL | bindings::__GFP_ZERO)?;
        let guest_phys = virt_to_phys(guest_mem);
        
        // Allocate VMID
        let vmid = {
            let mut current = NEXT_VMID.load(Ordering::Relaxed);
            loop {
                let next = if current > 255 { 1 } else { current + 1 };
                match NEXT_VMID.compare_exchange_weak(
                    current,
                    next,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break current,
                    Err(v) => current = v,
                }
            }
        };
        
        // Initialize stage-2 page tables
        let mut s2_pgtable = Stage2PageTable::new()?;
        
        // Map guest memory into stage-2 page tables
        // Guest IPA 0x40000000 -> Host PA guest_phys
        s2_pgtable.map_range(0x40000000, guest_phys, guest_mem_size)?;
        
        pr_info!("RKVM: VM created, VMID={}, guest_mem=0x{:x}, phys=0x{:x}, size={}\n",
                 vmid, guest_mem, guest_phys, guest_mem_size);
        
        Ok(Self {
            s2_pgtable,
            guest_mem,
            guest_phys,
            guest_mem_size,
            vmid,
            vcpu: None,
            created: true,
        })
    }
    
    /// Create a vCPU
    pub fn create_vcpu(&mut self) -> Result {
        if self.vcpu.is_some() {
            pr_err!("RKVM: vCPU already created\n");
            return Err(EEXIST);
        }
        
        let vtcr = Stage2PageTable::vtcr_value();
        let vcpu = KBox::new(RKvmVcpu::new(
            self.s2_pgtable.pgd_phys(),
            self.vmid,
            vtcr
        ), GFP_KERNEL)?;
        
        pr_info!("RKVM: vCPU created, PC=0x{:x}, HCR=0x{:x}, VTTBR=0x{:x}\n",
                 vcpu.regs.pc, vcpu.hcr_el2, vcpu.vttbr_el2);
        
        self.vcpu = Some(vcpu);
        Ok(())
    }
    
    /// Get mutable reference to vCPU
    pub fn vcpu_mut(&mut self) -> Result<&mut RKvmVcpu> {
        self.vcpu.as_deref_mut().ok_or(EINVAL)
    }
    
    /// Get reference to vCPU
    pub fn vcpu(&self) -> Result<&RKvmVcpu> {
        self.vcpu.as_deref().ok_or(EINVAL)
    }
    
    /// Copy guest code from userspace
    pub fn set_memory(&mut self, userspace_addr: VirtAddr, size: MemSize) -> Result {
        if size > self.guest_mem_size {
            pr_warn!("RKVM: Requested size larger than allocated memory\n");
            return Err(EINVAL);
        }
        
        // Copy from userspace
        copy_from_user(
            self.guest_mem,
            userspace_addr,
            size
        )?;
        
        // Flush instruction cache (Clean to PoU + Invalidate I-cache)
        flush_icache_range(
            self.guest_mem,
            self.guest_mem + size
        );
        
        // Also clean to PoC because guest runs with MMU off (uncached) initially
        clean_dcache_poc(
            self.guest_mem,
            size
        );
        
        pr_info!("RKVM: Copied {} bytes of guest code\n", size);
        Ok(())
    }
}

impl Drop for RKvmVm {
    fn drop(&mut self) {
        if self.guest_mem != 0 {
            kfree(self.guest_mem);
        }
    }
}

unsafe impl Send for RKvmVm {}
unsafe impl Sync for RKvmVm {}
