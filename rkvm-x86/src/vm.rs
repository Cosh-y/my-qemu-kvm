//! Virtual Machine management for x86_64

use alloc::vec::Vec;
use alloc::sync::Arc;
use kernel::{
    prelude::*,
    bindings,
}

use crate::types::*;
use crate::ept::EptPageTable;
use crate::vcpu::X86Vcpu;

pub struct PinnedMem {
    /// 保存所有的 page 指针
    /// 在 C 中是 struct page *
    pages: VVec<*mut bindings::page>, 
    /// 这一段内存的起始 HVA (Host Virtual Address)，用于调试或对齐检查
    hva: VirtAddr,
    /// 这段内存对应的 GPA (Guest Physical Address)
    gpa: PhysAddr,
    /// 内存大小
    size: MemSize,
}

impl PinnedMem {
    pub fn new(hva: VirtAddr, gpa: GuestPhysAddr, size: MemSize) -> Result<Self> {
        let page_count = (size + 4095) >> 12;
        
        let mut pages = Vec::with_capacity(page_count);
        
        let pinned_count = unsafe {
            bindings::pin_user_pages_fast(
                hva as u64,
                page_count as i32, 
                bindings::FOLL_WRITE | bindings::FOLL_LONGTERM,
                pages.as_mut_ptr()
            )
        };

        if pinned_count < 0 {
            return Err(Error::from_kernel_errno(pinned_count));
        }

        if pinned_count as usize != page_count {
            // 如果没 pin 全，需要把已经 pin 的释放掉，然后报错
            for &page in &pages[..pinned_count as usize] {
                unsafe {
                    bindings::unpin_user_page(page);
                }
            }
            return Err(Error::ENOMEM);
        }

        // 告诉 Vec 我们已经填入了数据
        unsafe { pages.set_len(pinned_count as usize) };

        Ok(Self {
            pages,
            hva,
            gpa,
            size,
        })
    }
    
    // 获取用于填入 EPT 的物理地址列表
    pub fn get_phys_addrs(&self) -> Vec<u64> {
        self.pages.iter().map(|&page| {
            unsafe { bindings::page_to_phys(page) as u64 }
        }).collect()
    }

    pub fn guest_phys_addr_base(&self) -> GuestPhysAddr {
        self.gpa
    }

    pub fn get_pages_count(&self) -> usize {
        self.pages.len()
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
    /// Guest memory mapping from userspace
    guest_mem: VVec<PinnedMem>,
    /// EPT page table
    ept: EptPageTable,
    /// VCPUs
    vcpus: Vec<Arc<Mutex<X86Vcpu>>>,
}

impl X86Vm {
    /// Create new VM (memory will be set later by userspace)
    pub fn new() -> Result<Self> {
        pr_info!("RKVM-x86: Creating VM\n");
        
        // Create EPT page table
        let ept = EptPageTable::new()?;
        
        Ok(Self {
            guest_mem: VVec::new(),
            ept,
            vcpus: Vec::new(),
        })
    }
    

    pub fn set_memory(&mut self, mapping: GuestMemoryMap) -> Result<()> {
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
        let hpas: Vec<u64> = pin_mem.get_phys_addrs();

        for i in 0..num_pages {
            
            // Map in EPT: GPA -> HPA
            self.ept.map_range(
                gpa,
                hpas[i],
                4096,
                bindings::EPT_MEM_TYPE_WB | bindings::EPT_FLAG_READ 
                    | bindings::EPT_FLAG_WRITE | bindings::EPT_FLAG_EXEC,
            )?;
            
            if i % 256 == 0 {
                pr_info!("  Mapped page {}/{}: GPA 0x{:x} -> HPA 0x{:x}\n", 
                         i + 1, num_pages, gpa, hpas[i]);
            }
            
            gpa += 4096;
        }
        
        pr_info!("RKVM-x86: Mapped {} pages in EPT\n", num_pages);
        
        // Store the mapping
        self.guest_mem.try_push(pin_mem)?;
        
        Ok(())
    }
    
    /// Create a new VCPU
    pub fn create_vcpu(&mut self) -> Result<Arc<Mutex<X86Vcpu>>> {
        let vcpu_id = self.vcpus.len();
        let ept_root = self.ept.root_pa();
        
        let vcpu = X86Vcpu::new(vcpu_id, ept_root)?;
        let vcpu = Arc::try_new(Mutex::new(vcpu))?;
        
        self.vcpus.try_push(vcpu.clone())?;
        pr_info!("RKVM-x86: Created VCPU #{}\n", vcpu_id);
        
        Ok(vcpu)
    }
    
    /// Get VCPU by ID
    pub fn get_vcpu(&self, vcpu_id: usize) -> Result<Arc<Mutex<X86Vcpu>>> {
        self.vcpus.get(vcpu_id)
            .ok_or(EINVAL)
            .map(|v| v.clone())
    }
    
    /// Get EPT root physical address
    pub fn ept_root(&self) -> PhysAddr {
        self.ept.root_pa()
    }
    
    /// Get number of VCPUs
    pub fn num_vcpus(&self) -> usize {
        self.vcpus.len()
    }
}

impl Drop for X86Vm {
    fn drop(&mut self) {
        pr_info!("Destroying VM\n");
    }
}