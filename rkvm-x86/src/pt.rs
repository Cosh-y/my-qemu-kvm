//! build a tmp page table to start up the guest VM
#![allow(missing_docs)]

use kernel::prelude::*;
use crate::types::*;
use kernel::alloc::Vec;
use kernel::alloc::allocator::Kmalloc;

#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum PageTableFlags {
    Present = 1 << 0,
    Writable = 1 << 1,
    UserAccessible = 1 << 2,
    WriteThrough = 1 << 3,
    CacheDisable = 1 << 4,
    Accessed = 1 << 5,
    Dirty = 1 << 6,
    HugePage = 1 << 7,
    Global = 1 << 8,
    NoExecute = 1 << 63,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub fn new(phys_addr: GuestPhysAddr, flags: u64) -> Self {
        Self((phys_addr & 0x000fffff_fffff000) | (flags & 0xfff0000000000fff))
    }

    pub fn addr(&self) -> GuestPhysAddr {
        self.0 & 0x000fffff_fffff000
    }

    pub fn flags(&self) -> u64 {
        self.0 & 0xfff0000000000fff
    }

    pub fn is_present(&self) -> bool {
        (self.flags() & PageTableFlags::Present as u64) != 0
    }

    pub fn is_huge_page(&self) -> bool {
        (self.flags() & PageTableFlags::HugePage as u64) != 0
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; 512],
}

impl PageTable {
    pub fn empty() -> Self {
        Self {
            entries: [PageTableEntry(0); 512],
        }
    }

    pub fn set_entry(&mut self, index: usize, entry: PageTableEntry) {
        self.entries[index] = entry;
    }

    pub fn get_entry(&self, index: usize) -> PageTableEntry {
        self.entries[index]
    }

    pub fn base_addr(&self) -> VirtAddr {
        self as *const _ as VirtAddr
    }
}

pub static mut PML4_GPA: GuestPhysAddr = 0;

pub struct TmpPageTables {
    pub pml4: Vec<PageTableEntry, Kmalloc>,
    pub pdpt: Vec<PageTableEntry, Kmalloc>,
}

impl TmpPageTables {
    pub fn new() -> Result<Self> {
        let mut pml4 = Vec::with_capacity(512, GFP_KERNEL)?;
        for _ in 0..512 {
            pml4.push(PageTableEntry(0), GFP_KERNEL)?;
        }

        let mut pdpt = Vec::with_capacity(512, GFP_KERNEL)?;
        for _ in 0..512 {
            pdpt.push(PageTableEntry(0), GFP_KERNEL)?;
        }

        Ok(Self {
            pml4,
            pdpt,
        })
    }

    pub fn pml4_base_addr(&self) -> VirtAddr {
        self.pml4.as_ptr() as VirtAddr
    }

    pub fn pdpt_base_addr(&self) -> VirtAddr {
        self.pdpt.as_ptr() as VirtAddr
    }

    /// Map the first 4GB of memory using 1GB pages
    pub fn setup_identity_map_4GB(&mut self, load_addr: GuestPhysAddr, base_addr: GuestPhysAddr) -> Result<()> {
        if base_addr % 0x4000_0000 != 0 { // base_addr 1GB aligned
            return Err(EINVAL);
        }
        if load_addr % 0x1000 != 0 { // load_addr 4KB aligned
            return Err(EINVAL);
        }
        for i in 0..4 {
            let phys_addr = ((i as GuestPhysAddr) << 30) + base_addr;
            let index = (phys_addr >> 30) as usize; // index represents guest virt addr
            let entry = PageTableEntry::new(
                phys_addr,
                (PageTableFlags::Present as u64)
                    | (PageTableFlags::Writable as u64)
                    | (PageTableFlags::HugePage as u64),
            );
            if index < self.pdpt.len() {
                self.pdpt[index] = entry;
            }
        }

        // Set up PML4 entry to point to PDPT, PDPT will be load to GuestPhysAddr 0x1000
        let pml4_entry = PageTableEntry::new(
            load_addr + 0x1000,
            (PageTableFlags::Present as u64) | (PageTableFlags::Writable as u64),
        );
        if !self.pml4.is_empty() {
            self.pml4[0] = pml4_entry;
        }
        Ok(())
    }
}
