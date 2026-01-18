// 用于自己包装那些
// 1. 我们的 rust kernel module 中用到了的
// 2. rust for linux 的 kernel crate 中没有提供安全封装的
// 3. bindgen 没能生成的（bindgen 用于为 Linux 原有的 C 内核函数生成 unsafe rust 封装）
// 内核 C 函数。

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <asm/memory.h>
#include <asm/cacheflush.h>

// 包装 page_address (static inline)
void *rkvm_page_address(const struct page *page)
{
    return page_address(page);
}

// 包装 phys_to_virt (宏/inline)
void *rkvm_phys_to_virt(phys_addr_t x)
{
    return phys_to_virt(x);
}

// 包装 virt_to_phys (宏/inline)
phys_addr_t rkvm_virt_to_phys(volatile void *address)
{
    return virt_to_phys(address);
}

// 包装 vmalloc_to_phys
phys_addr_t rkvm_vmalloc_to_phys(void *address)
{
    struct page *page = vmalloc_to_page(address);
    if (!page)
        return 0;
    return page_to_phys(page) + offset_in_page(address);
}

/* --- 内存分配/释放 --- */

// 包装 kmalloc (static inline)
void *rkvm_kmalloc(size_t size, gfp_t flags)
{
    return kmalloc(size, flags);
}

// 包装 kfree (为了统一接口，虽然 bindings 里有)
void rkvm_kfree(const void *block)
{
    kfree(block);
}

// 包装 free_page (宏)
void rkvm_free_page(unsigned long addr)
{
    free_page(addr);
}

// 包装 copy_from_user (static inline)
// 返回未能复制的字节数，0 表示成功
unsigned long rkvm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
    return copy_from_user(to, from, n);
}

void rkvm_flush_icache_range(unsigned long start, unsigned long end)
{
    flush_icache_range(start, end);
}
