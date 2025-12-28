/*
 * kvm_hvc.c - HVC call wrappers for EL2 access from EL1
 * 
 * This file provides C wrappers for HVC calls to the EL2 stub.
 * These functions allow the EL1 kernel module to access EL2 functionality.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/sysreg.h>
#include "kvm_hvc.h"

/*
 * __kvm_hvc_call - Make an HVC call to EL2
 * 
 * This is the low-level HVC call function.
 * Arguments are passed in x0-x7, result in x0.
 */
static inline long __kvm_hvc_call(unsigned long func,
                                   unsigned long arg1,
                                   unsigned long arg2,
                                   unsigned long arg3,
                                   unsigned long arg4)
{
    register long x0 asm("x0") = func;
    register long x1 asm("x1") = arg1;
    register long x2 asm("x2") = arg2;
    register long x3 asm("x3") = arg3;
    register long x4 asm("x4") = arg4;
    
    asm volatile(
        "hvc #0\n"
        : "+r" (x0)
        : "r" (x1), "r" (x2), "r" (x3), "r" (x4)
        : "memory"
    );
    
    return x0;
}

/*
 * kvm_hvc_init_hyp - Initialize hypervisor state
 * 
 * This MUST be called after installing our EL2 stub to properly
 * initialize EL2 state, especially clearing TPIDR_EL2.
 * 
 * Returns: 0 on success, negative on error
 */
int kvm_hvc_init_hyp(void)
{
    long ret;
    
    pr_info("mini_kvm: Initializing hypervisor state\n");
    
    ret = __kvm_hvc_call(HVC_KVM_INIT_HYP, 0, 0, 0, 0);
    
    if (ret != 0) {
        pr_err("mini_kvm: HVC_KVM_INIT_HYP failed: %ld\n", ret);
        return -EIO;
    }
    
    pr_info("mini_kvm: ✓ Hypervisor state initialized (TPIDR_EL2 cleared)\n");
    return 0;
}

/*
 * kvm_hvc_set_vectors - Set VBAR_EL2 via kernel's HVC_SET_VECTORS
 * 
 * This uses the Linux kernel's standard HVC call to replace the EL2 stub.
 * Note: Kernel uses HVC 0 for both GET and SET, distinguished by x1:
 *   - x1 == 0: GET_VECTORS
 *   - x1 != 0: SET_VECTORS (x1 = new vector address)
 * 
 * @vectors: Physical address of new exception vectors
 * Returns: 0 on success, negative on error
 */
int kvm_hvc_set_vectors(unsigned long vectors)
{
    long ret;
    
    pr_info("mini_kvm: Setting VBAR_EL2 to 0x%lx via HVC 0\n", vectors);
    
    /* HVC 0 with x1 = vectors means SET_VECTORS */
    ret = __kvm_hvc_call(0, vectors, 0, 0, 0);
    
    if (ret != 0) {
        pr_err("mini_kvm: HVC SET_VECTORS failed: %ld\n", ret);
        return -EIO;
    }
    
    return 0;
}

/*
 * kvm_hvc_get_vectors - Get VBAR_EL2 via kernel's HVC_GET_VECTORS
 * 
 * @Returns: VBAR_EL2 value, or 0 on error
 */
unsigned long kvm_hvc_get_vectors(void)
{
    long ret;
    
    /* HVC 0 with x1 = 0 means GET_VECTORS */
    ret = __kvm_hvc_call(0, 0, 0, 0, 0);
    
    return (unsigned long)ret;
}

/*
 * kvm_hvc_vcpu_run - Run a vCPU via HVC
 * 
 * @vcpu_ptr: Pointer to vcpu structure
 * Returns: 0 on success
 */
int kvm_hvc_vcpu_run(void *vcpu_ptr)
{
    long ret;
    
    ret = __kvm_hvc_call(HVC_KVM_VCPU_RUN, (unsigned long)vcpu_ptr, 0, 0, 0);
    
    return (int)ret;
}

/*
 * kvm_hvc_write_sysreg - Write an EL2 system register via HVC
 * 
 * @reg: Register ID (from enum el2_sysreg)
 * @value: Value to write
 * Returns: 0 on success
 */
int kvm_hvc_write_sysreg(enum el2_sysreg reg, u64 value)
{
    long ret;
    
    ret = __kvm_hvc_call(HVC_KVM_WRITE_SYSREG, reg, value, 0, 0);
    
    if (ret != 0) {
        pr_err("mini_kvm: Failed to write EL2 register %d\n", reg);
        return -EIO;
    }
    
    return 0;
}

/*
 * kvm_hvc_read_sysreg - Read an EL2 system register via HVC
 * 
 * @reg: Register ID (from enum el2_sysreg)
 * Returns: Register value, or -1 on error
 */
u64 kvm_hvc_read_sysreg(enum el2_sysreg reg)
{
    long ret;
    
    ret = __kvm_hvc_call(HVC_KVM_READ_SYSREG, reg, 0, 0, 0);
    
    return (u64)ret;
}

/* Convenience wrappers for specific registers */

int kvm_hvc_write_vtcr_el2(u64 value)
{
    return kvm_hvc_write_sysreg(EL2_VTCR, value);
}

int kvm_hvc_write_vbar_el2(u64 value)
{
    return kvm_hvc_write_sysreg(EL2_VBAR, value);
}

int kvm_hvc_write_hcr_el2(u64 value)
{
    return kvm_hvc_write_sysreg(EL2_HCR, value);
}

int kvm_hvc_write_vttbr_el2(u64 value)
{
    return kvm_hvc_write_sysreg(EL2_VTTBR, value);
}

int kvm_hvc_write_tpidr_el2(u64 value)
{
    return kvm_hvc_write_sysreg(EL2_TPIDR, value);
}

u64 kvm_hvc_read_vtcr_el2(void)
{
    return kvm_hvc_read_sysreg(EL2_VTCR);
}

u64 kvm_hvc_read_vbar_el2(void)
{
    return kvm_hvc_read_sysreg(EL2_VBAR);
}

u64 kvm_hvc_read_hcr_el2(void)
{
    return kvm_hvc_read_sysreg(EL2_HCR);
}
