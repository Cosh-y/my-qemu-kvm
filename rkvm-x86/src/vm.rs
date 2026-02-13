//! Virtual Machine management for x86_64
#![allow(missing_docs)]

use kernel::{
    prelude::*,
    bindings,
};

use crate::types::*;
use crate::device::GuestMemoryMapMessage;
use crate::ept::EptPageTable;
use crate::vcpu::X86Vcpu;

unsafe impl Send for PinnedMem {}
unsafe impl Sync for PinnedMem {}

pub struct PinnedMem {
    /// 保存所有的 page 指针
    /// 在 C 中是 struct page *
    pages: Vec<*mut bindings::page, kernel::alloc::allocator::Kmalloc>, 
    pages_len: usize,
    /// 这一段内存的起始 HVA (Host Virtual Address)，用于调试或对齐检查
    hva: VirtAddr,
    /// 这段内存对应的 GPA (Guest Physical Address)
    gpa: GuestPhysAddr,
    /// 内存大小
    size: MemSize,
}

impl PinnedMem {
    pub fn new(hva: VirtAddr, gpa: GuestPhysAddr, size: MemSize) -> Result<Self> {
        let page_count = size >> 12;
        pr_info!("page_count: {}\n", page_count);
        let mut pages = Vec::with_capacity(page_count, GFP_KERNEL)?;
        for _ in 0..page_count {
            pages.push(core::ptr::null_mut(), GFP_KERNEL)?;
        }
        
        let pinned_count = unsafe {
            bindings::pin_user_pages_fast(
                hva,
                page_count as i32, 
                bindings::FOLL_WRITE | bindings::FOLL_LONGTERM,
                pages.as_mut_ptr()
            )
        };

        if pinned_count < 0 {
            return Err(Error::from_errno(pinned_count));
        }

        if pinned_count as usize != page_count {
            // 如果没 pin 全，需要把已经 pin 的释放掉，然后报错
            for &page in &pages[..pinned_count as usize] {
                unsafe {
                    bindings::unpin_user_page(page);
                }
            }
            return Err(ENOMEM);
        }

        Ok(Self {
            pages,
            pages_len: pinned_count as usize,
            hva,
            gpa,
            size,
        })
    }
    
    // 获取用于填入 EPT 的物理地址列表
    pub fn get_phys_addrs(&self) -> Result<Vec<PhysAddr, kernel::alloc::allocator::Kmalloc>> {
        let mut result = Vec::with_capacity(self.pages_len, GFP_KERNEL)?;
        for &page in &self.pages {
            let hva = crate::wrap::page_address(page) as VirtAddr;
            let pa = crate::wrap::virt_to_phys(hva);
            result.push(pa, GFP_KERNEL)?;
        }
        Ok(result)
    }

    pub fn guest_phys_addr_base(&self) -> GuestPhysAddr {
        self.gpa
    }

    pub fn virt_addr_base(&self) -> VirtAddr {
        self.hva
    }

    pub fn get_pages_count(&self) -> usize {
        self.pages_len
    }
}

impl Drop for PinnedMem {
    fn drop(&mut self) {
        for &page in &self.pages {
            unsafe {
                bindings::unpin_user_page(page);
            }
        }
    }
}

/// Virtual machine structure
pub struct X86Vm {
    guest_mem: Vec<PinnedMem, kernel::alloc::allocator::Kmalloc>,
    ept: EptPageTable,
    vcpu: Box<X86Vcpu, kernel::alloc::allocator::Kmalloc>,
}

impl X86Vm {
    /// Create new VM (memory will be set later by userspace)
    pub fn new() -> Result<Self> {
        pr_info!("RKVM-x86: Creating VM\n");
        
        // Create EPT page table
        let ept = EptPageTable::new()?;
        
        Ok(Self {
            guest_mem: Vec::new(),
            ept,
            vcpu: Box::new(X86Vcpu::new()?, GFP_KERNEL)?,
        })
    }
    

    pub fn set_memory(&mut self, mapping: &GuestMemoryMapMessage) -> Result<()> {
        pr_info!("RKVM-x86: Setting guest memory:\n");
        pr_info!("  Host VA: 0x{:x}\n", mapping.host_virt_addr);
        pr_info!("  Guest PA: 0x{:x}\n", mapping.guest_phys_addr);
        pr_info!("  Size: {} bytes\n", mapping.memory_size);
        
        if mapping.memory_size == 0 {
            pr_err!("RKVM-x86: Invalid memory size: 0\n");
            return Err(EINVAL);
        }
        
        // Map the memory region in EPT page by page
        let pin_mem: PinnedMem = PinnedMem::new(
            mapping.host_virt_addr,
            mapping.guest_phys_addr,
            mapping.memory_size,
        )?;
        let num_pages = pin_mem.get_pages_count();
        let mut gpa = pin_mem.guest_phys_addr_base();
        let hpas = pin_mem.get_phys_addrs()?;

        for i in 0..num_pages {
            
            // Map in EPT: GPA -> HPA
            self.ept.map_range(
                gpa,
                hpas[i],
                4096,
            )?;
            
            pr_info!("  Mapped page {}/{}: GPA 0x{:x} -> HPA 0x{:x}\n", 
                         i + 1, num_pages, gpa, hpas[i]);
            
            gpa += 4096;
        }
        
        pr_info!("RKVM-x86: Mapped {} pages in EPT\n", num_pages);
        
        // Store the mapping
        self.guest_mem.push(pin_mem, GFP_KERNEL)?;
        
        Ok(())
    }

    pub fn get_memory(&self) -> &Vec<PinnedMem, kernel::alloc::allocator::Kmalloc> {
        &self.guest_mem
    }
    
    /// Create a new VCPU
    pub fn create_vcpu(&mut self) -> Result<()> {        
        // check or do nothing?   
        Ok(())
    }
    
    /// Get VCPU by ID
    pub fn get_vcpu(&self) -> Result<&X86Vcpu> {
        Ok(&self.vcpu)
    }

    pub fn get_vcpu_mut(&mut self) -> Result<&mut X86Vcpu> {
        Ok(&mut self.vcpu)
    }

    pub fn get_eptp(&self) -> u64 {
        self.ept.eptp()
    }
}

impl Drop for X86Vm {
    fn drop(&mut self) {
        pr_info!("Destroying VM\n");
    }
}