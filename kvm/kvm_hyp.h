/*
 * kvm_hyp.h - Hypervisor definitions and structures
 * 
 * This header defines the data structures and offsets used by both
 * C code and assembly code for world switching.
 */

#ifndef __KVM_HYP_H__
#define __KVM_HYP_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef uint8_t u8;
typedef uint64_t u64;
#endif

/* 
 * ============================================================================
 * VCPU STRUCTURE OFFSETS - SINGLE SOURCE OF TRUTH
 * These offsets are used by both C and assembly code
 * ============================================================================
 */
#define VCPU_REGS_OFFSET        0
#define VCPU_SYSREGS_OFFSET     512
#define VCPU_VTTBR_OFFSET       1024
#define VCPU_HCR_OFFSET         1032
#define VCPU_ESR_OFFSET         1040
#define VCPU_FAR_OFFSET         1048
#define VCPU_HPFAR_OFFSET       1056
#define VCPU_VTCR_OFFSET        1064

/* System register offsets within sysregs structure */
#define SYSREG_SCTLR_EL1        0
#define SYSREG_TTBR0_EL1        8
#define SYSREG_TTBR1_EL1        16
#define SYSREG_TCR_EL1          24
#define SYSREG_MAIR_EL1         32
#define SYSREG_VBAR_EL1         40
#define SYSREG_SP_EL1           48
#define SYSREG_ELR_EL1          56
#define SYSREG_SPSR_EL1         64
#define SYSREG_HOST_ELR_EL2     72      /* Host PC (ELR_EL2) */

/* 
 * ============================================================================
 * PER-CPU HOST CONTEXT OFFSETS
 * Each CPU has its own host context storage to prevent overwrites
 * ============================================================================
 */
#define MAX_CPUS                8       /* Maximum supported CPUs */

/* Host context structure size and offsets */
#define HOST_REGS_SIZE          96      /* 12 registers * 8 bytes (x19-x30) */
#define HOST_SYSREGS_SIZE       80      /* System registers + Host PC */
#define HOST_CONTEXT_SIZE       (HOST_REGS_SIZE + HOST_SYSREGS_SIZE)

/* Offsets within per-CPU host context */
#define HOST_REGS_OFFSET        0
#define HOST_SYSREGS_OFFSET     96

#ifndef __ASSEMBLY__
/*
 * ============================================================================
 * C LANGUAGE STRUCTURES - NOT VISIBLE TO ASSEMBLY
 * These are only compiled when included from C files
 * ============================================================================
 */

/*
 * Guest CPU register state
 */
struct kvm_cpu_regs {
    u64 x[31];              /* x0-x30 general purpose registers */
    u64 pc;                 /* Program counter */
    u64 pstate;             /* Processor state */
    u64 sp;                 /* Stack pointer */
};

/*
 * Guest system registers (EL1 state)
 */
struct kvm_sys_regs {
    u64 sctlr_el1;          /* System Control Register */
    u64 ttbr0_el1;          /* Translation Table Base Register 0 */
    u64 ttbr1_el1;          /* Translation Table Base Register 1 */
    u64 tcr_el1;            /* Translation Control Register */
    u64 mair_el1;           /* Memory Attribute Indirection Register */
    u64 vbar_el1;           /* Vector Base Address Register */
    u64 sp_el1;             /* Stack Pointer EL1 */
    u64 elr_el1;            /* Exception Link Register */
    u64 spsr_el1;           /* Saved Program Status Register */
    
    /* Additional important registers */
    u64 esr_el1;            /* Exception Syndrome Register */
    u64 far_el1;            /* Fault Address Register */
    u64 par_el1;            /* Physical Address Register */
    u64 contextidr_el1;     /* Context ID Register */
    u64 tpidr_el1;          /* Thread ID Register */
    u64 tpidrro_el1;        /* Read-Only Thread ID Register */
    u64 amair_el1;          /* Auxiliary Memory Attribute Indirection Register */
};

/*
 * Stage-2 page table entry (descriptor)
 */
struct s2_pte {
    u64 val;
};

/* Stage-2 page table descriptor bits */
#define S2_PTE_VALID        (1UL << 0)
#define S2_PTE_TABLE        (1UL << 1)
#define S2_PTE_AF           (1UL << 10)    /* Access flag */
#define S2_PTE_SH_INNER     (3UL << 8)     /* Inner shareable */
#define S2_PTE_S2AP_RW      (3UL << 6)     /* Read/write */
#define S2_PTE_MEMATTR_DEV  (0UL << 2)     /* Device memory */
#define S2_PTE_MEMATTR_NORM (0xFUL << 2)   /* Normal memory */

/* Page table configuration */
#define S2_PGDIR_SHIFT      30              /* 1GB per entry at level 1 */
#define S2_PUD_SHIFT        21              /* 2MB per entry at level 2 */
#define S2_PMD_SHIFT        12              /* 4KB per entry at level 3 */
#define S2_PTRS_PER_TABLE   512

/* Stage-2 translation configuration */
#define S2_VTCR_PS_40BIT    (2UL << 16)    /* 40-bit PA size */
#define S2_VTCR_TG0_4K      (0UL << 14)    /* 4KB granule */
#define S2_VTCR_SH0_INNER   (3UL << 12)    /* Inner shareable */
#define S2_VTCR_ORGN0_WBWA  (1UL << 10)    /* Normal, write-back, write-allocate */
#define S2_VTCR_IRGN0_WBWA  (1UL << 8)     /* Normal, write-back, write-allocate */
#define S2_VTCR_SL0_L1      (1UL << 6)     /* Start at level 1 */
#define S2_VTCR_T0SZ_25BIT  (25UL << 0)    /* 39-bit IPA space (64-39=25) */

/*
 * VCPU structure - complete vCPU state
 */
struct kvm_vcpu {
    /* Guest register state - must be at offset 0 for assembly access */
    struct kvm_cpu_regs regs;
    
    /* Padding to reach offset 512 */
    u8 _pad1[512 - sizeof(struct kvm_cpu_regs)];
    
    /* Guest system registers - must be at offset 512 */
    struct kvm_sys_regs sys_regs;
    
    /* Padding to reach offset 1024 */
    u8 _pad2[1024 - 512 - sizeof(struct kvm_sys_regs)];
    
    /* Stage-2 page table base (VTTBR_EL2) - must be at offset 1024 */
    u64 vttbr_el2;
    
    /* HCR_EL2 configuration - must be at offset 1032 */
    u64 hcr_el2;
    
    /* Exception information - saved on VM exit */
    u64 esr_el2;            /* Exception syndrome */
    u64 far_el2;            /* Fault address */
    u64 hpfar_el2;          /* Stage-2 fault address */
    u64 vtcr_el2;           /* Stage-2 translation control */
    
    /* Stage-2 page table */
    u64 *s2_pgd;            /* Stage-2 page global directory (physical address) */
    
    /* VM context */
    void *vm;               /* Back pointer to VM structure */
    
    /* Run state */
    int exit_reason;
    bool request_exit;
};

/*
 * VM structure - represents a virtual machine instance
 */
struct kvm_vm {
    struct kvm_vcpu *vcpu;
    
    /* Guest physical memory */
    void *guest_mem;            /* Kernel virtual address */
    unsigned long guest_phys;   /* Host physical address */
    size_t guest_mem_size;
    
    /* Stage-2 page tables */
    u64 *s2_pgd;                /* Stage-2 page global directory */
    unsigned long s2_pgd_phys;  /* Physical address of S2 PGD */
    u64 vtcr_el2;               /* Stage-2 translation control */
    
    /* VM ID for VTTBR */
    u64 vmid;
    
    int created;
};

/* HCR_EL2 configuration flags for guest execution */
#define HCR_VM      (1UL << 0)   /* Virtualization MMU enable */
#define HCR_SWIO    (1UL << 1)   /* Set/Way Invalidate Override */
#define HCR_PTW     (1UL << 2)   /* Protected Table Walk */
#define HCR_FMO     (1UL << 3)   /* FIQ Mask Override */
#define HCR_IMO     (1UL << 4)   /* IRQ Mask Override */
#define HCR_AMO     (1UL << 5)   /* SError Mask Override */
#define HCR_VF      (1UL << 6)   /* Virtual FIQ */
#define HCR_VI      (1UL << 7)   /* Virtual IRQ */
#define HCR_VSE     (1UL << 8)   /* Virtual SError */
#define HCR_FB      (1UL << 9)   /* Force Broadcast */
#define HCR_BSU     (3UL << 10)  /* Barrier Shareability Upgrade */
#define HCR_DC      (1UL << 12)  /* Default Cacheable */
#define HCR_TWI     (1UL << 13)  /* Trap WFI */
#define HCR_TWE     (1UL << 14)  /* Trap WFE */
#define HCR_TID0    (1UL << 15)  /* Trap ID Group 0 */
#define HCR_TID1    (1UL << 16)  /* Trap ID Group 1 */
#define HCR_TID2    (1UL << 17)  /* Trap ID Group 2 */
#define HCR_TID3    (1UL << 18)  /* Trap ID Group 3 */
#define HCR_TSC     (1UL << 19)  /* Trap SMC */
#define HCR_TIDCP   (1UL << 20)  /* Trap IMPLEMENTATION DEFINED */
#define HCR_TACR    (1UL << 21)  /* Trap Auxiliary Control Registers */
#define HCR_TSW     (1UL << 22)  /* Trap Set/Way */
#define HCR_TPCP    (1UL << 23)  /* Trap IMPLEMENTATION DEFINED 2 */
#define HCR_TPU     (1UL << 24)  /* Trap Cache Maintenance */
#define HCR_TTLB    (1UL << 25)  /* Trap TLB Maintenance */
#define HCR_TVM     (1UL << 26)  /* Trap Virtual Memory */
#define HCR_TGE     (1UL << 27)  /* Trap General Exceptions */
#define HCR_TDZ     (1UL << 28)  /* Trap DC ZVA */
#define HCR_HCD     (1UL << 29)  /* HVC Disable */
#define HCR_TRVM    (1UL << 30)  /* Trap Reads of Virtual Memory */
#define HCR_RW      (1UL << 31)  /* Register Width (1=AArch64) */

/* Default HCR_EL2 value for running guest */
#define HCR_GUEST_FLAGS (HCR_VM | HCR_RW | HCR_IMO | HCR_FMO | \
                         HCR_AMO | HCR_TWI | HCR_TSC)

#endif /* __ASSEMBLY__ */

#endif /* __KVM_HYP_H__ */
