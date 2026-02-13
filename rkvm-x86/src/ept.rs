//! EPT (Extended Page Tables) implementation for x86_64
//! 
//! Provides 4-level paging for guest physical to host physical translation
#![allow(missing_docs)]

use kernel::bindings;
use kernel::prelude::*;
use crate::types::*;

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

unsafe impl Send for EptPageTable {}
unsafe impl Sync for EptPageTable {}

/// EPT page table structure (4-level: PML4 -> PDPT -> PD -> PT)
pub struct EptPageTable {
    pml4_page: *mut bindings::page,
    pml4_phys: PhysAddr,
}

impl EptPageTable {
    /// Create new EPT page table
    pub fn new() -> Result<Self> {
        use kernel::bindings;
        use crate::wrap;
        
        let pml4_page = unsafe { bindings::alloc_pages(bindings::GFP_KERNEL | bindings::__GFP_ZERO, 0) };
        let pml4_virt = wrap::page_address(pml4_page);
        let pml4_phys = wrap::virt_to_phys(pml4_virt);
        
        // Clear PML4 table
        unsafe {
            core::ptr::write_bytes(pml4_virt as *mut u8, 0, 4096);
        }
        
        Ok(Self {
            pml4_page,
            pml4_phys,
        })
    }
    
    /// Get physical address of PML4 (for EPTP)
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4_phys
    }
    
    /// Get EPTP value for VMCS
    /// Format: bits 11:0 = EPT config, bits 51:12 = PML4 physical address
    pub fn eptp(&self) -> u64 {
        let mut eptp = self.pml4_phys;
        
        // EPT Memory Type: Write-back (6 << 0)
        eptp |= 6;
        
        // EPT Page-walk length: 4 (3 << 3, means 4 levels)
        eptp |= 3 << 3;
        
        // Enable accessed and dirty flags
        eptp |= 1 << 6;
        
        eptp
    }
    
    /// Map guest physical address range to host physical address
    /// Uses 2MB huge pages for simplicity
    pub fn map_range(&mut self, gpa: GuestPhysAddr, hpa: PhysAddr, size: MemSize) -> Result<()> {
        let mut offset: u64 = 0;
        
        while offset < size as u64 {
            let gpa_aligned = gpa + offset;
            let hpa_aligned = hpa + offset;
            
            self.map_4kb_page(gpa_aligned, hpa_aligned)?;
            offset += 4 * 1024; // 4KB
        }
        
        Ok(())
    }
    
    /// Map a single 4KB page
    /// 4 level page table walk: PML4 -> PDPT -> PD -> PT
    /// EPT's page table entries contains host physical addresses, use guest physical address as index to walk
    fn map_4kb_page(&mut self, gpa: u64, hpa: u64) -> Result<()> {
        // Extract page table indices
        let pml4_idx = ((gpa >> EPT_PML4_SHIFT) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> EPT_PDPT_SHIFT) & 0x1FF) as usize;
        let pd_idx = ((gpa >> EPT_PD_SHIFT) & 0x1FF) as usize;
        let pt_idx = ((gpa >> EPT_PT_SHIFT) & 0x1FF) as usize;
        
        // Get PML4 table
        let pml4_virt = crate::wrap::page_address(self.pml4_page);
        let pml4 = unsafe { 
            core::slice::from_raw_parts_mut(pml4_virt as *mut EptPte, EPT_PTRS_PER_TABLE) 
        };
        
        // Get or create PDPT
        if !pml4[pml4_idx].is_present() {
            use kernel::bindings;
            use crate::wrap;
            
            let pdpt_page = unsafe { bindings::alloc_pages(bindings::GFP_KERNEL | bindings::__GFP_ZERO, 0) };
            let pdpt_virt = wrap::page_address(pdpt_page);
            let pdpt_phys = wrap::virt_to_phys(pdpt_virt);
            
            // Clear PDPT
            unsafe {
                core::ptr::write_bytes(pdpt_virt as *mut u8, 0, 4096);
            }
            
            // Install PDPT in PML4
            let mut pte = EptPte::new();
            pte.set_addr(pdpt_phys);
            pte.0 |= EptPte::READ | EptPte::WRITE | EptPte::EXECUTE;
            pml4[pml4_idx] = pte;
            
            // Keep reference to avoid dropping
            core::mem::forget(pdpt_page);
        }
        
        // Get PDPT table
        let pdpt_phys = pml4[pml4_idx].addr();
        let pdpt_virt = crate::wrap::phys_to_virt(pdpt_phys);
        let pdpt = unsafe {
            core::slice::from_raw_parts_mut(pdpt_virt as *mut EptPte, EPT_PTRS_PER_TABLE)
        };
        
        // Get or create PD
        if !pdpt[pdpt_idx].is_present() {
            use kernel::bindings;
            use crate::wrap;
            
            let pd_page = unsafe { bindings::alloc_pages(bindings::GFP_KERNEL | bindings::__GFP_ZERO, 0) };
            let pd_virt = wrap::page_address(pd_page);
            let pd_phys = wrap::virt_to_phys(pd_virt);
            
            // Clear PD
            unsafe {
                core::ptr::write_bytes(pd_virt as *mut u8, 0, 4096);
            }
            
            // Install PD in PDPT
            let mut pte = EptPte::new();
            pte.set_addr(pd_phys);
            pte.0 |= EptPte::READ | EptPte::WRITE | EptPte::EXECUTE;
            pdpt[pdpt_idx] = pte;
            
            core::mem::forget(pd_page);
        }
        
        // Get PD table
        let pd_phys = pdpt[pdpt_idx].addr();
        let pd_virt = crate::wrap::phys_to_virt(pd_phys);
        let pd = unsafe {
            core::slice::from_raw_parts_mut(pd_virt as *mut EptPte, EPT_PTRS_PER_TABLE)
        };
        
        // Get or create PT
        if !pd[pd_idx].is_present() {
            use kernel::bindings;
            use crate::wrap;
            
            let pt_page = unsafe { bindings::alloc_pages(bindings::GFP_KERNEL | bindings::__GFP_ZERO, 0) };
            let pt_virt = wrap::page_address(pt_page);
            let pt_phys = wrap::virt_to_phys(pt_virt);

            // Clear PT
            unsafe {
                core::ptr::write_bytes(pt_virt as *mut u8, 0, 4096);
            }

            // Install PT in PD
            let mut pte = EptPte::new();
            pte.set_addr(pt_phys);
            pte.0 |= EptPte::READ | EptPte::WRITE | EptPte::EXECUTE;
            pd[pd_idx] = pte;

            core::mem::forget(pt_page);
        }

        // Get PT table
        let pt_phys = pd[pd_idx].addr();
        let pt_virt = crate::wrap::phys_to_virt(pt_phys);
        let pt = unsafe {
            core::slice::from_raw_parts_mut(pt_virt as *mut EptPte, EPT_PTRS_PER_TABLE)
        };

        // Install 4KB page in PT
        let mut pte = EptPte::new();
        pte.set_addr(hpa & !0xFFF); // Align to 4KB
        pte.0 |= EptPte::READ | EptPte::WRITE | EptPte::EXECUTE;
        pte.0 |= EptPte::MEMORY_TYPE_WB; // Write-back memory type
        pte.0 |= EptPte::IGNORE_PAT;
        pt[pt_idx] = pte;
        
        Ok(())
    }
    
    /// Translate guest physical address to host physical address
    pub fn translate(&self, gpa: u64) -> Result<u64> {
        let pml4_idx = ((gpa >> EPT_PML4_SHIFT) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> EPT_PDPT_SHIFT) & 0x1FF) as usize;
        let pd_idx = ((gpa >> EPT_PD_SHIFT) & 0x1FF) as usize;
        let pt_idx = ((gpa >> EPT_PT_SHIFT) & 0x1FF) as usize;
        let offset = gpa & 0xFFF; // 4KB offset
        
        // Walk page table
        let pml4_virt = crate::wrap::page_address(self.pml4_page);
        let pml4 = unsafe {
            core::slice::from_raw_parts(pml4_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pml4[pml4_idx].is_present() {
            return Err(EFAULT);
        }
        
        let pdpt_phys = pml4[pml4_idx].addr();
        let pdpt_virt = crate::wrap::phys_to_virt(pdpt_phys);
        let pdpt = unsafe {
            core::slice::from_raw_parts(pdpt_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pdpt[pdpt_idx].is_present() {
            return Err(EFAULT);
        }
        
        let pd_phys = pdpt[pdpt_idx].addr();
        let pd_virt = crate::wrap::phys_to_virt(pd_phys);
        let pd = unsafe {
            core::slice::from_raw_parts(pd_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pd[pd_idx].is_present() {
            return Err(EFAULT);
        }
        
        let pt_phys = pd[pd_idx].addr();
        let pt_virt = crate::wrap::phys_to_virt(pt_phys);
        let pt = unsafe {
            core::slice::from_raw_parts(pt_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pt[pt_idx].is_present() {
            return Err(EFAULT);
        }
        
        let page_phys = pt[pt_idx].addr();
        Ok(page_phys + offset)
    }
}


impl Drop for EptPageTable {
    fn drop(&mut self) {
        // Clean up page tables
        // In a real implementation, we should walk the tree and free all pages
        // For now, we rely on the kernel's page allocator tracking
    }
}