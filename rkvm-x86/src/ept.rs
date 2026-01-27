//! EPT (Extended Page Tables) implementation for x86_64
//! 
//! Provides 4-level paging for guest physical to host physical translation

use crate::types::*;
use kernel::prelude::*;
use kernel::page::{alloc_pages, Page};

/// EPT page table structure (4-level: PML4 -> PDPT -> PD -> PT)
pub struct EptPageTable {
    pml4_page: Page,
    pml4_phys: PhysAddr,
}

impl EptPageTable {
    /// Create new EPT page table
    pub fn new() -> Result<Self> {
        let pml4_page = alloc_pages(0)?;
        let pml4_phys = pml4_page.phys_addr();
        let pml4_virt = pml4_page.virt_addr();
        
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
            
            self.map_2mb_page(gpa_aligned, hpa_aligned)?;
            offset += 2 * 1024 * 1024; // 2MB
        }
        
        Ok(())
    }
    
    /// Map a single 2MB page
    fn map_2mb_page(&mut self, gpa: u64, hpa: u64) -> Result<()> {
        // Extract page table indices
        let pml4_idx = ((gpa >> EPT_PML4_SHIFT) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> EPT_PDPT_SHIFT) & 0x1FF) as usize;
        let pd_idx = ((gpa >> EPT_PD_SHIFT) & 0x1FF) as usize;
        
        // Get PML4 table
        let pml4_virt = self.pml4_page.virt_addr();
        let pml4 = unsafe { 
            core::slice::from_raw_parts_mut(pml4_virt as *mut EptPte, EPT_PTRS_PER_TABLE) 
        };
        
        // Get or create PDPT
        if !pml4[pml4_idx].is_present() {
            let pdpt_page = alloc_pages(0)?;
            let pdpt_phys = pdpt_page.phys_addr();
            let pdpt_virt = pdpt_page.virt_addr();
            
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
        let pdpt_virt = phys_to_virt(pdpt_phys)?;
        let pdpt = unsafe {
            core::slice::from_raw_parts_mut(pdpt_virt as *mut EptPte, EPT_PTRS_PER_TABLE)
        };
        
        // Get or create PD
        if !pdpt[pdpt_idx].is_present() {
            let pd_page = alloc_pages(0)?;
            let pd_phys = pd_page.phys_addr();
            let pd_virt = pd_page.virt_addr();
            
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
        let pd_virt = phys_to_virt(pd_phys)?;
        let pd = unsafe {
            core::slice::from_raw_parts_mut(pd_virt as *mut EptPte, EPT_PTRS_PER_TABLE)
        };
        
        // Create 2MB page mapping in PD
        let mut pte = EptPte::new();
        pte.set_addr(hpa & !0x1FFFFF); // Align to 2MB
        pte.0 |= EptPte::READ | EptPte::WRITE | EptPte::EXECUTE;
        pte.0 |= EptPte::LARGE_PAGE; // Mark as 2MB page
        pte.0 |= EptPte::MEMORY_TYPE_WB; // Write-back memory type
        pte.0 |= EptPte::IGNORE_PAT;
        pd[pd_idx] = pte;
        
        Ok(())
    }
    
    /// Translate guest physical address to host physical address
    pub fn translate(&self, gpa: u64) -> Result<u64> {
        let pml4_idx = ((gpa >> EPT_PML4_SHIFT) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> EPT_PDPT_SHIFT) & 0x1FF) as usize;
        let pd_idx = ((gpa >> EPT_PD_SHIFT) & 0x1FF) as usize;
        let offset = gpa & 0x1FFFFF; // 2MB offset
        
        // Walk page table
        let pml4_virt = self.pml4_page.virt_addr();
        let pml4 = unsafe {
            core::slice::from_raw_parts(pml4_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pml4[pml4_idx].is_present() {
            return Err(EFAULT);
        }
        
        let pdpt_phys = pml4[pml4_idx].addr();
        let pdpt_virt = phys_to_virt(pdpt_phys)?;
        let pdpt = unsafe {
            core::slice::from_raw_parts(pdpt_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pdpt[pdpt_idx].is_present() {
            return Err(EFAULT);
        }
        
        let pd_phys = pdpt[pdpt_idx].addr();
        let pd_virt = phys_to_virt(pd_phys)?;
        let pd = unsafe {
            core::slice::from_raw_parts(pd_virt as *const EptPte, EPT_PTRS_PER_TABLE)
        };
        
        if !pd[pd_idx].is_present() {
            return Err(EFAULT);
        }
        
        let page_phys = pd[pd_idx].addr();
        Ok(page_phys + offset)
    }
}

/// Convert physical address to virtual address
/// This is a simple helper - in real kernel should use proper mapping
fn phys_to_virt(phys: u64) -> Result<usize> {
    // In Linux kernel, physical memory is typically mapped at a fixed offset
    // For simplicity, we assume direct mapping (this needs kernel support)
    Ok((phys + 0xffff888000000000) as usize)
}

impl Drop for EptPageTable {
    fn drop(&mut self) {
        // Clean up page tables
        // In a real implementation, we should walk the tree and free all pages
        // For now, we rely on the kernel's page allocator tracking
    }
}