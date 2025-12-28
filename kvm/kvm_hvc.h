/*
 * kvm_hvc.h - HVC call definitions and interface
 * 
 * This header defines HVC function numbers and system register IDs
 * used for EL2 access from EL1. This is the single source of truth
 * for all HVC-related constants.
 */

#ifndef __KVM_HVC_H__
#define __KVM_HVC_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint64_t u64;
#endif

/* 
 * ============================================================================
 * HVC FUNCTION NUMBERS - SINGLE SOURCE OF TRUTH
 * These numbers must match between C code and assembly code
 * ============================================================================
 */

/* 
 * Standard ARM HVC calls - use kernel's definitions from asm/virt.h
 * We don't redefine HVC_GET_VECTORS and HVC_SET_VECTORS here to avoid conflicts.
 * The kernel defines:
 *   HVC_GET_VECTORS = 0
 *   HVC_SET_VECTORS = 0 (same as GET, distinguished by having argument or not)
 *   HVC_RESET_VECTORS = 2
 */

/* KVM-specific HVC calls (0x100-0x1FF) - our custom extensions */
#define HVC_KVM_INIT_HYP        0x100   /* Initialize hypervisor state */
#define HVC_KVM_VCPU_RUN        0x101   /* Run a vCPU (world switch) */
#define HVC_KVM_WRITE_SYSREG    0x102   /* Write EL2 system register */
#define HVC_KVM_READ_SYSREG     0x103   /* Read EL2 system register */

/* 
 * ============================================================================
 * EL2 SYSTEM REGISTER IDs - SINGLE SOURCE OF TRUTH
 * Used by HVC_KVM_WRITE_SYSREG and HVC_KVM_READ_SYSREG
 * ============================================================================
 */

/* System register IDs for HVC calls */
#define EL2_SYSREG_VTCR         0       /* VTCR_EL2 */
#define EL2_SYSREG_VBAR         1       /* VBAR_EL2 */
#define EL2_SYSREG_HCR          2       /* HCR_EL2 */
#define EL2_SYSREG_VTTBR        3       /* VTTBR_EL2 */
#define EL2_SYSREG_TPIDR        4       /* TPIDR_EL2 */

#if defined(__KERNEL__) && !defined(__ASSEMBLY__)
/*
 * ============================================================================
 * C LANGUAGE DECLARATIONS - NOT VISIBLE TO ASSEMBLY
 * ============================================================================
 */

/* C enum version for type safety in C code */
enum el2_sysreg {
    EL2_VTCR  = EL2_SYSREG_VTCR,
    EL2_VBAR  = EL2_SYSREG_VBAR,
    EL2_HCR   = EL2_SYSREG_HCR,
    EL2_VTTBR = EL2_SYSREG_VTTBR,
    EL2_TPIDR = EL2_SYSREG_TPIDR,
};

/* Function prototypes for HVC call wrappers */
int kvm_hvc_init_hyp(void);
int kvm_hvc_set_vectors(unsigned long vectors);
unsigned long kvm_hvc_get_vectors(void);
int kvm_hvc_vcpu_run(void *vcpu_ptr);
int kvm_hvc_write_sysreg(enum el2_sysreg reg, u64 value);
u64 kvm_hvc_read_sysreg(enum el2_sysreg reg);

/* Convenience wrappers for specific registers */
int kvm_hvc_write_vtcr_el2(u64 value);
int kvm_hvc_write_vbar_el2(u64 value);
int kvm_hvc_write_hcr_el2(u64 value);
int kvm_hvc_write_vttbr_el2(u64 value);
int kvm_hvc_write_tpidr_el2(u64 value);
u64 kvm_hvc_read_vtcr_el2(void);
u64 kvm_hvc_read_vbar_el2(void);
u64 kvm_hvc_read_hcr_el2(void);
#endif /* __KERNEL__ && !__ASSEMBLY__ */

#endif /* __KVM_HVC_H__ */
