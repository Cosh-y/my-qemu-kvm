/*
 * mini_kvm.h - Shared interface between kernel module and userspace VMM
 * 
 * This header defines the ioctl commands and data structures used for
 * communication between the Rust VMM (userspace) and the C kernel module.
 */

#ifndef MINI_KVM_H
#define MINI_KVM_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* ioctl magic number */
#define MINIKVM_MAGIC 0xAE

/* ioctl commands */
#define MINIKVM_CREATE_VM       _IO(MINIKVM_MAGIC, 1)
#define MINIKVM_CREATE_VCPU     _IO(MINIKVM_MAGIC, 2)
#define MINIKVM_RUN             _IOR(MINIKVM_MAGIC, 3, struct minikvm_run_state)
#define MINIKVM_SET_REGS        _IOW(MINIKVM_MAGIC, 4, struct minikvm_regs)
#define MINIKVM_GET_REGS        _IOR(MINIKVM_MAGIC, 5, struct minikvm_regs)
#define MINIKVM_SET_MEM         _IOW(MINIKVM_MAGIC, 6, struct minikvm_mem_region)

/* Guest register state (ARM64) */
struct minikvm_regs {
    __u64 x[31];            /* General purpose registers x0-x30 */
    __u64 pc;               /* Program counter */
    __u64 pstate;           /* Processor state */
    __u64 sp;               /* Stack pointer */
};

/* Memory region mapping */
struct minikvm_mem_region {
    __u64 guest_phys_addr;  /* Guest physical address (IPA) */
    __u64 memory_size;      /* Size of the region */
    __u64 userspace_addr;   /* Userspace virtual address */
};

/* VM exit reasons */
enum minikvm_exit_reason {
    MINIKVM_EXIT_UNKNOWN = 0,
    MINIKVM_EXIT_MMIO = 1,
    MINIKVM_EXIT_HLT = 2,
    MINIKVM_EXIT_SHUTDOWN = 3,
    MINIKVM_EXIT_INTERNAL_ERROR = 4,
};

/* MMIO access information */
struct minikvm_mmio {
    __u64 phys_addr;        /* Physical address accessed */
    __u64 data;             /* Data read/written */
    __u32 len;              /* Access length (1, 2, 4, 8 bytes) */
    __u8  is_write;         /* 1 for write, 0 for read */
    __u8  padding[3];       /* Explicit padding to 8-byte boundary */
};

/* Internal error information */
struct minikvm_internal_error {
    __u32 error_code;       /* Error code */
    __u32 padding;          /* Explicit padding to 8-byte boundary */
};

/* Run state returned by MINIKVM_RUN 
 * Note: We don't use union to ensure consistent size calculation
 * between C and Rust. Use exit_reason to determine which fields are valid.
 */
struct minikvm_run_state {
    __u32 exit_reason;              /* Why did we exit? */
    __u32 padding;                  /* Padding for alignment */
    struct minikvm_mmio mmio;       /* Valid when exit_reason == MINIKVM_EXIT_MMIO */
    struct minikvm_internal_error internal_error; /* Valid when exit_reason == MINIKVM_EXIT_INTERNAL_ERROR */
};

/* Constants */
#define MINIKVM_MAX_VCPUS 1
#define MINIKVM_MAX_MEM_REGIONS 8

#endif /* MINI_KVM_H */
