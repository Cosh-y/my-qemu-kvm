//! Stage-2 page table management
//! 
//! This module handles stage-2 (guest physical -> host physical) address translation

use kernel::prelude::*;
use kernel::bindings;
use crate::types::*;
use crate::wrap::*;

/// Stage-2 page table structure
pub(crate) struct Stage2PageTable {
    pgd: *mut u64,
    pgd_phys: PhysAddr,
}

impl Stage2PageTable {
    /// Create a new stage-2 page table
    pub(crate) fn new() -> Result<Self> {
        // Allocate PGD (level 1 table)
        let pgd = Self::alloc_table()?;
        let pgd_phys = virt_to_phys(pgd as VirtAddr);
        
        pr_info!("RKVM: Stage-2 PGD allocated at PA 0x{:x}\n", pgd_phys);
        
        Ok(Self { pgd, pgd_phys })
    }
    
    /// Allocate a page table page
    fn alloc_table() -> Result<*mut u64> {
        unsafe {
            // order 为 0 表示分配 1 个页面
            let page = bindings::alloc_pages(bindings::GFP_KERNEL | bindings::__GFP_ZERO, 0);
            if page.is_null() {
                return Err(ENOMEM);
            }
            Ok(page_address(page) as *mut u64)
        }
    }
    
    /// Free a page table page
    fn free_table(table: *mut u64) {
        if !table.is_null() {
            free_page(table as VirtAddr);
        }
    }
    
    /// Map a range of guest IPA to host PA
    pub(crate) fn map_range(&mut self, ipa_start: GuestPhysAddr, pa_start: PhysAddr, size: MemSize) -> Result {
        pr_info!("RKVM: Mapping IPA 0x{:x} -> PA 0x{:x}, size 0x{:x}\n",
                ipa_start, pa_start, size);
        
        let mut ipa = ipa_start;
        let mut pa = pa_start;
        let block_size: u64 = 1u64 << S2_PUD_SHIFT;
        
        while ipa < ipa_start + (size as u64) {
            self.map_block(ipa, pa)?;
            ipa += block_size;
            pa += block_size;
        }
        
        Ok(())
    }
    
    /// Map a single 2MB block
    fn map_block(&mut self, ipa: GuestPhysAddr, pa: PhysAddr) -> Result {
        let pgd_idx = ((ipa >> S2_PGDIR_SHIFT) & (S2_PTRS_PER_TABLE - 1) as u64) as usize;
        let pud_idx = ((ipa >> S2_PUD_SHIFT) & (S2_PTRS_PER_TABLE - 1) as u64) as usize;
        
        unsafe {
            let pgd = self.pgd;
            
            // Check if PUD exists
            if (*pgd.add(pgd_idx) & S2Pte::VALID) == 0 {
                // Allocate PUD table
                let pud = Self::alloc_table()?;
                let pud_phys = virt_to_phys(pud as VirtAddr);
                *pgd.add(pgd_idx) = pud_phys | S2Pte::TABLE | S2Pte::VALID;
            }
            
            let pud_phys = *pgd.add(pgd_idx) & !0xFFF;
            let pud = phys_to_virt(pud_phys) as *mut u64;
            
            // Create 2MB block mapping
            let pte_val = (pa & !(block_size() - 1)) |
                          S2Pte::VALID |
                          S2Pte::AF |
                          S2Pte::SH_INNER |
                          S2Pte::S2AP_RW |
                          S2Pte::MEMATTR_NORM;
            
            *pud.add(pud_idx) = pte_val;
        }
        
        Ok(())
    }
    
    /// Get physical address of PGD
    pub(crate) fn pgd_phys(&self) -> PhysAddr {
        self.pgd_phys
    }
    
    /// Generate VTCR_EL2 value
    pub(crate) fn vtcr_value() -> u64 {
        S2_VTCR_PS_40BIT |
        S2_VTCR_TG0_4K |
        S2_VTCR_SH0_INNER |
        S2_VTCR_ORGN0_WBWA |
        S2_VTCR_IRGN0_WBWA |
        S2_VTCR_SL0_L1 |
        S2_VTCR_T0SZ_25BIT
    }
}

impl Drop for Stage2PageTable {
    fn drop(&mut self) {
        // Free PUD tables
        unsafe {
            for i in 0..S2_PTRS_PER_TABLE {
                let entry = *self.pgd.add(i);
                if (entry & S2Pte::VALID) != 0 {
                    let pud_phys = entry & !0xFFF;
                    let pud = phys_to_virt(pud_phys) as *mut u64;
                    Self::free_table(pud);
                }
            }
            
            // Free PGD
            Self::free_table(self.pgd);
        }
    }
}

// Constants for block size calculation
const fn block_size() -> u64 {
    1u64 << S2_PUD_SHIFT
}
