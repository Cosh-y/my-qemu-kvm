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

// Convert virtual address to physical
phys_addr_t rkvm_virt_to_phys(void *addr)
{
    return virt_to_phys(addr);
}

// Convert physical to virtual address
void *rkvm_phys_to_virt(phys_addr_t addr)
{
    return phys_to_virt(addr);
}

void *rkvm_page_address(const struct page *page)
{
    return page_address(page);
}

// Copy from user space to kernel space
unsigned long rkvm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    return copy_from_user(to, from, n);
}

// Copy from kernel space to user space
unsigned long rkvm_copy_to_user(void __user *to, const void *from, unsigned long n)
{
    return copy_to_user(to, from, n);
}
