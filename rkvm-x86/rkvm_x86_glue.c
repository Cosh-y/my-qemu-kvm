// rkvm_x86_glue.c - C wrapper functions for kernel APIs
//
// Provides wrappers for kernel functions that:
// 1. Are not available in Rust-for-Linux kernel crate
// 2. Are macros or inline functions
// 3. Need special handling

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

// Convert user virtual address to physical address
// This walks the current process's page tables
phys_addr_t rkvm_x86_user_virt_to_phys(unsigned long uva, struct page **out_page)
{
    struct page *page = NULL;
    phys_addr_t pa = 0;
    int ret;

    ret = pin_user_pages_fast(uva, 1, FOLL_WRITE | FOLL_LONGTERM, &page);

    if (ret == 1 && page) {
        pa = page_to_phys(page) + offset_in_page(uva);
        if (out_page)
            *out_page = page;
        else
            unpin_user_pages(page, 1);
            pa = 0;
    } else {
        pa = 0;
    }
    return pa;
}

// Get a zeroed page
unsigned long rkvm_x86_get_zeroed_page(void)
{
    return get_zeroed_page(GFP_KERNEL);
}

// Free a page
void rkvm_x86_free_page(unsigned long addr)
{
    free_page(addr);
}

// Convert virtual address to physical
phys_addr_t rkvm_x86_virt_to_phys(void *addr)
{
    return virt_to_phys(addr);
}

// Convert physical to virtual address
void *rkvm_x86_phys_to_virt(phys_addr_t addr)
{
    return phys_to_virt(addr);
}

// Flush icache (on x86 this is a no-op, but included for completeness)
void rkvm_x86_flush_icache_range(unsigned long start, unsigned long end)
{
    // On x86, instruction cache is coherent with data cache
    // No explicit flush needed
    (void)start;
    (void)end;
}

// Copy from userspace
unsigned long rkvm_x86_copy_from_user(void *to, const void __user *from, 
                                       unsigned long n)
{
    return copy_from_user(to, from, n);
}

// Copy to userspace  
unsigned long rkvm_x86_copy_to_user(void __user *to, const void *from,
                                     unsigned long n)
{
    return copy_to_user(to, from, n);
}