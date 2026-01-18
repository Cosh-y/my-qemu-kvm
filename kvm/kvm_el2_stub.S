/*
 * kvm_el2_stub.S - EL2 stub that handles all EL2 exceptions
 * 
 * This is the ONLY exception vector table at EL2.
 * It handles:
 * 1. HVC calls from EL1 host (for KVM operations)
 * 2. Exceptions/interrupts from guest (EL1 guest -> EL2)
 * 3. World switching between host and guest
 * 
 * Architecture:
 * - This stub stays installed at VBAR_EL2 permanently
 * - It delegates world switch logic to kvm_hyp.S functions
 * - All exceptions (from both host and guest) come here first
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/virt.h>
#include "kvm_hyp.h"
#include "kvm_hvc.h"

/* 
 * CRITICAL: Define ventry macro to ensure 128-byte alignment.
 * Without this, the vector table entries will be packed, causing
 * the CPU to jump to the wrong location (or into zeros) upon exception.
 */
.macro mventry target
    .align 7        /* Align to 2^7 = 128 bytes */
    b \target
.endm

/*
 * Exception vector entry macro is provided by asm/assembler.h
 * No need to redefine it here
 */

.text
.align 11

/*
 * __kvm_el2_stub_vectors - EL2 exception vectors (THE ONLY EL2 VECTOR TABLE)
 * 
 * This vector table handles ALL EL2 exceptions:
 * - HVC calls from host (EL1) for KVM operations
 * - Sync/IRQ/FIQ/Error from guest (EL1) during VM execution
 */
SYM_CODE_START(__kvm_el2_stub_vectors)
    /* Current EL with SP0 */
    mventry el2_stub_sync_invalid
    mventry el2_stub_irq_invalid
    mventry el2_stub_fiq_invalid
    mventry el2_stub_error_invalid
    
    /* Current EL with SPx */
    mventry el2_stub_sync_invalid
    mventry el2_stub_irq_invalid
    mventry el2_stub_fiq_invalid
    mventry el2_stub_error_invalid
    
    /* Lower EL using AArch64 */
    mventry el2_stub_el1_sync         /* Sync from EL1 (host HVC or guest trap) */
    mventry el2_stub_el1_irq          /* IRQ from EL1 (host or guest) */
    mventry el2_stub_el1_fiq          /* FIQ from EL1 (host or guest) */
    mventry el2_stub_el1_error        /* SError from EL1 (host or guest) */
    
    /* Lower EL using AArch32 */
    mventry el2_stub_sync_invalid
    mventry el2_stub_irq_invalid
    mventry el2_stub_fiq_invalid
    mventry el2_stub_error_invalid
SYM_CODE_END(__kvm_el2_stub_vectors)

/*
 * Invalid exception handlers with debug information
 * 
 * These handlers save system register values into general-purpose
 * registers before entering infinite loop, allowing inspection via
 * debugger (e.g., QEMU monitor or GDB).
 */
SYM_CODE_START_LOCAL(el2_stub_sync_invalid)
    /* Save debug info to x0-x7 for easy viewing in QEMU */
    mrs x0, esr_el2
    mrs x1, elr_el2
    mrs x2, far_el2
    mrs x3, hpfar_el2
    mrs x4, tpidr_el2
    mrs x5, vbar_el2
    mrs x6, hcr_el2
    mrs x7, vttbr_el2
    
    /* Mark which handler we are in */
    mov x8, #0x200
    
1:  wfi
    b 1b
SYM_CODE_END(el2_stub_sync_invalid)

SYM_CODE_START_LOCAL(el2_stub_irq_invalid)
    /* Save exception information */
    mrs x20, esr_el2
    mrs x21, elr_el2
    mrs x22, far_el2
    mrs x23, hpfar_el2
    mrs x24, tpidr_el2
    mrs x25, vbar_el2
    mrs x26, hcr_el2
    mrs x27, vttbr_el2
    mov x28, #0x280          /* Exception vector offset (EL2h IRQ) */
    mrs x29, spsr_el2
    mov x30, lr
    
1:  wfi
    b 1b
SYM_CODE_END(el2_stub_irq_invalid)

SYM_CODE_START_LOCAL(el2_stub_fiq_invalid)
    /* Save exception information */
    mrs x20, esr_el2
    mrs x21, elr_el2
    mrs x22, far_el2
    mrs x23, hpfar_el2
    mrs x24, tpidr_el2
    mrs x25, vbar_el2
    mrs x26, hcr_el2
    mrs x27, vttbr_el2
    mov x28, #0x300          /* Exception vector offset (EL2h FIQ) */
    mrs x29, spsr_el2
    mov x30, lr
    
1:  wfi
    b 1b
SYM_CODE_END(el2_stub_fiq_invalid)

SYM_CODE_START_LOCAL(el2_stub_error_invalid)
    /* Save exception information */
    mrs x20, esr_el2
    mrs x21, elr_el2
    mrs x22, far_el2
    mrs x23, hpfar_el2
    mrs x24, tpidr_el2
    mrs x25, vbar_el2
    mrs x26, hcr_el2
    mrs x27, vttbr_el2
    mov x28, #0x380          /* Exception vector offset (EL2h Error) */
    mrs x29, spsr_el2
    mov x30, lr
    
1:  wfi
    b 1b
SYM_CODE_END(el2_stub_error_invalid)

/*
 * el2_stub_el1_sync - Handle synchronous exceptions from EL1
 * 
 * This is the CRITICAL handler that distinguishes:
 * 1. HVC from host (ELR_EL2 points to host code)
 * 2. Sync exception from guest (ELR_EL2 points to guest code)
 * 
 * Strategy: First check if it's an HVC. If it's HVC_KVM_INIT_HYP, handle it
 * immediately without checking TPIDR_EL2 (since that's what we're initializing).
 * Otherwise, check TPIDR_EL2 to determine guest vs host context.
 */
SYM_CODE_START_LOCAL(el2_stub_el1_sync)    
    /* This is an HVC - check if it's HVC_KVM_INIT_HYP (must handle first!) */
    cmp x0, #HVC_KVM_INIT_HYP
    b.eq hvc_kvm_init_hyp       /* Initialize hypervisor state immediately */
    
    /* For all other HVCs, check if we're in guest context */
    mrs x9, tpidr_el2
    cmp x9, #0
    b.ne guest_sync_exit        /* Non-zero = guest HVC, handle as guest exit */
    
    /* Zero = host context HVC, dispatch based on function number in x0 */
    /* Note: HVC_GET_VECTORS and HVC_SET_VECTORS are both 0 in kernel,
     * distinguished by having an argument (x1) or not. */
    cmp x0, #0                  /* Is it HVC 0 (GET/SET_VECTORS)? */
    b.ne 2f                     /* No, check other custom HVCs */
    
    /* HVC 0: Check if x1 is non-zero (SET) or zero (GET) */
    cmp x1, #0
    b.eq hvc_get_vectors        /* x1 == 0: GET_VECTORS */
    b hvc_set_vectors           /* x1 != 0: SET_VECTORS */
    
2:  cmp x0, #HVC_KVM_VCPU_RUN
    b.eq hvc_kvm_vcpu_run
    
    cmp x0, #HVC_KVM_WRITE_SYSREG
    b.eq hvc_kvm_write_sysreg
    
    cmp x0, #HVC_KVM_READ_SYSREG
    b.eq hvc_kvm_read_sysreg
    
    /* Unknown HVC */
    mov x0, #-1
    eret
    
1:  /* Not HVC - could be guest sync exception, check TPIDR_EL2 */
    mrs x9, tpidr_el2
    cmp x9, #0
    b.ne guest_sync_exit        /* Non-zero = guest context */
    /* Zero = invalid sync exception from host */
    b el2_stub_sync_invalid
SYM_CODE_END(el2_stub_el1_sync)

/*
 * guest_sync_exit - Handle synchronous exception from guest
 * 
 * The guest was running and hit a sync exception (HVC, data abort, etc.)
 * We need to:
 * 1. Save guest context
 * 2. Clear guest context marker
 * 3. Return to host
 */
SYM_CODE_START_LOCAL(guest_sync_exit)
    /* Get vcpu pointer from TPIDR_EL2 */
    mrs x18, tpidr_el2
    
    /* Save guest general purpose registers */
    add x0, x18, #VCPU_REGS_OFFSET
    stp x0, x1, [x0, #0]
    stp x2, x3, [x0, #16]
    stp x4, x5, [x0, #32]
    stp x6, x7, [x0, #48]
    stp x8, x9, [x0, #64]
    stp x10, x11, [x0, #80]
    stp x12, x13, [x0, #96]
    stp x14, x15, [x0, #112]
    stp x16, x17, [x0, #128]
    stp x18, x19, [x0, #144]
    stp x20, x21, [x0, #160]
    stp x22, x23, [x0, #176]
    stp x24, x25, [x0, #192]
    stp x26, x27, [x0, #208]
    stp x28, x29, [x0, #224]
    str x30, [x0, #240]
    
    /* Save guest PC, PSTATE, SP */
    mrs x1, elr_el2
    mrs x2, spsr_el2
    mrs x3, sp_el1
    str x1, [x0, #248]      /* PC */
    str x2, [x0, #256]      /* PSTATE */
    str x3, [x0, #264]      /* SP */
    
    /* Save guest system registers */
    add x5, x18, #VCPU_SYSREGS_OFFSET
    
    mrs x1, sctlr_el1
    mrs x2, ttbr0_el1
    stp x1, x2, [x5, #SYSREG_SCTLR_EL1]
    
    mrs x1, ttbr1_el1
    mrs x2, tcr_el1
    stp x1, x2, [x5, #SYSREG_TTBR1_EL1]
    
    mrs x1, mair_el1
    mrs x2, vbar_el1
    stp x1, x2, [x5, #SYSREG_MAIR_EL1]
    
    mrs x1, sp_el1
    mrs x2, elr_el1
    stp x1, x2, [x5, #SYSREG_SP_EL1]
    
    mrs x1, spsr_el1
    str x1, [x5, #SYSREG_SPSR_EL1]
    
    /* Save exception information */
    mrs x1, esr_el2
    str x1, [x18, #VCPU_ESR_OFFSET]
    
    mrs x1, far_el2
    str x1, [x18, #VCPU_FAR_OFFSET]
    
    mrs x1, hpfar_el2
    str x1, [x18, #VCPU_HPFAR_OFFSET]
    
    /* Clear guest context marker */
    msr tpidr_el2, xzr
    
    /* 
     * CRITICAL: Reset HCR_EL2 for Host execution
     * We must disable Stage 2 translation (VM=0) and traps (IMO=0, FMO=0)
     * otherwise the Host will crash or get stuck in interrupt loops.
     * We only keep HCR_RW (bit 31) to ensure EL1 is AArch64.
     */
    mov x0, #0x80000000     /* HCR_RW */
    msr hcr_el2, x0
    isb
    
    /* Get CPU ID from MPIDR_EL1 for per-CPU storage */
    mrs x0, mpidr_el1
    and x0, x0, #0xFF        /* Extract Aff0 (CPU ID within cluster) */
    
    /* Calculate per-CPU context offset: cpu_id * HOST_CONTEXT_SIZE */
    mov x1, #HOST_CONTEXT_SIZE
    mul x0, x0, x1
    
    /* Get base address of per-CPU host contexts */
    adr_l x1, __kvm_host_contexts
    add x0, x1, x0           /* x0 = &__kvm_host_contexts[cpu_id] */
    
    /* Restore host system registers from per-CPU storage */
    add x1, x0, #HOST_SYSREGS_OFFSET
    
    ldp x2, x3, [x1, #0]
    msr sctlr_el1, x2
    msr ttbr0_el1, x3
    
    ldp x2, x3, [x1, #16]
    msr ttbr1_el1, x2
    msr tcr_el1, x3
    
    ldp x2, x3, [x1, #32]
    msr mair_el1, x2
    msr vbar_el1, x3
    
    ldp x2, x3, [x1, #48]
    msr sp_el1, x2
    msr elr_el1, x3
    
    ldr x2, [x1, #64]
    msr spsr_el1, x2
    
    /* Restore Host PC (ELR_EL2) */
    ldr x2, [x1, #72]
    msr elr_el2, x2
    
    /* Restore host callee-saved registers from per-CPU storage */
    add x1, x0, #HOST_REGS_OFFSET
    ldp x19, x20, [x1, #0]
    ldp x21, x22, [x1, #16]
    ldp x23, x24, [x1, #32]
    ldp x25, x26, [x1, #48]
    ldp x27, x28, [x1, #64]
    ldp x29, x30, [x1, #80]
    
    /* Set up SPSR_EL2 for return to host */
    mov x2, #0x3c5          /* EL1h mode, IRQ/FIQ masked */
    msr spsr_el2, x2
    
    /* Return value: 0 = success */
    mov x0, #0
    
    /* Return to host */
    eret
SYM_CODE_END(guest_sync_exit)

/*
 * el2_stub_el1_irq - Handle IRQ from EL1
 * 
 * Could be from host or guest. Check TPIDR_EL2 to determine.
 */
SYM_CODE_START_LOCAL(el2_stub_el1_irq)
    mrs x9, tpidr_el2
    cmp x9, #0
    b.ne guest_irq_exit     /* Guest context */
    
    /* Host IRQ - just return, let host handle it */
    eret
SYM_CODE_END(el2_stub_el1_irq)

/*
 * guest_irq_exit - IRQ while guest was running
 */
SYM_CODE_START_LOCAL(guest_irq_exit)
    /* Same as guest_sync_exit - save state and return to host */
    b guest_sync_exit
SYM_CODE_END(guest_irq_exit)

/*
 * el2_stub_el1_fiq - Handle FIQ from EL1
 */
SYM_CODE_START_LOCAL(el2_stub_el1_fiq)
    mrs x9, tpidr_el2
    cmp x9, #0
    b.ne guest_sync_exit    /* Guest context */
    eret                     /* Host context */
SYM_CODE_END(el2_stub_el1_fiq)

/*
 * el2_stub_el1_error - Handle SError from EL1
 */
SYM_CODE_START_LOCAL(el2_stub_el1_error)
    mrs x9, tpidr_el2
    cmp x9, #0
    b.ne guest_sync_exit    /* Guest context */
    eret                     /* Host context */
SYM_CODE_END(el2_stub_el1_error)

/*
 * HVC Handlers
 */

/*
 * hvc_kvm_init_hyp - Initialize hypervisor state
 * 
 * This MUST be called after installing our EL2 stub to properly
 * initialize EL2 state, especially clearing TPIDR_EL2 which is
 * used as a guest context marker.
 * 
 * Without this, stale values in TPIDR_EL2 can cause HVC handlers
 * to incorrectly branch to guest_sync_exit.
 */
SYM_CODE_START_LOCAL(hvc_kvm_init_hyp)
    /* Clear TPIDR_EL2 (guest context marker) */
    msr tpidr_el2, xzr
    
    /* Reset HCR_EL2 to safe host defaults */
    mov x1, #0x80000000     /* HCR_RW (bit 31) - EL1 is AArch64 */
    msr hcr_el2, x1
    isb
    
    /* Clear VTTBR_EL2 */
    msr vttbr_el2, xzr
    
    /* Success */
    mov x0, #0
    eret
SYM_CODE_END(hvc_kvm_init_hyp)

/*
 * hvc_get_vectors - Get current VBAR_EL2
 */
SYM_CODE_START_LOCAL(hvc_get_vectors)
    mrs x0, vbar_el2
    eret
SYM_CODE_END(hvc_get_vectors)

/*
 * hvc_set_vectors - Set VBAR_EL2
 * Input: x1 = new vector address
 */
SYM_CODE_START_LOCAL(hvc_set_vectors)
    msr vbar_el2, x1
    isb
    mov x0, #0
    eret
SYM_CODE_END(hvc_set_vectors)

/*
 * hvc_kvm_vcpu_run - Run a vCPU (world switch from host to guest)
 * Input: x1 = vcpu pointer
 * 
 * This is the KEY function that implements world switching.
 * It uses the logic from kvm_hyp.S but is called via HVC from host.
 * 
 * Flow:
 * 1. Save host context
 * 2. Load guest context from vcpu structure
 * 3. Set guest context marker (TPIDR_EL2 = vcpu)
 * 4. ERET to guest
 * 5. (Guest runs at EL1)
 * 6. On guest exception -> trap to guest_sync_exit above
 * 7. guest_sync_exit saves guest state and returns here
 */
SYM_CODE_START_LOCAL(hvc_kvm_vcpu_run)
    /* Save vcpu pointer */
    mov x18, x1
    
    /* Get CPU ID from MPIDR_EL1 for per-CPU storage */
    mrs x0, mpidr_el1
    and x0, x0, #0xFF        /* Extract Aff0 (CPU ID within cluster) */
    
    /* Calculate per-CPU context offset: cpu_id * HOST_CONTEXT_SIZE */
    mov x1, #HOST_CONTEXT_SIZE
    mul x0, x0, x1
    
    /* Get base address of per-CPU host contexts */
    adr_l x1, __kvm_host_contexts
    add x0, x1, x0           /* x0 = &__kvm_host_contexts[cpu_id] */
    
    /* Save host callee-saved registers to per-CPU storage */
    add x1, x0, #HOST_REGS_OFFSET
    stp x19, x20, [x1, #0]
    stp x21, x22, [x1, #16]
    stp x23, x24, [x1, #32]
    stp x25, x26, [x1, #48]
    stp x27, x28, [x1, #64]
    stp x29, x30, [x1, #80]
    
    /* Save host system registers to per-CPU storage */
    add x1, x0, #HOST_SYSREGS_OFFSET
    
    mrs x2, sctlr_el1
    mrs x3, ttbr0_el1
    stp x2, x3, [x1, #0]
    
    mrs x2, ttbr1_el1
    mrs x3, tcr_el1
    stp x2, x3, [x1, #16]
    
    mrs x2, mair_el1
    mrs x3, vbar_el1
    stp x2, x3, [x1, #32]
    
    mrs x2, sp_el1
    mrs x3, elr_el1
    stp x2, x3, [x1, #48]
    
    mrs x2, spsr_el1
    str x2, [x1, #64]
    
    /* Save Host PC (ELR_EL2) */
    mrs x2, elr_el2
    str x2, [x1, #72]
    
    /* Load guest system registers from vcpu structure */
    add x1, x18, #VCPU_SYSREGS_OFFSET
    
    ldp x2, x3, [x1, #SYSREG_SCTLR_EL1]
    msr sctlr_el1, x2
    msr ttbr0_el1, x3
    
    ldp x2, x3, [x1, #SYSREG_TTBR1_EL1]
    msr ttbr1_el1, x2
    msr tcr_el1, x3
    
    ldp x2, x3, [x1, #SYSREG_MAIR_EL1]
    msr mair_el1, x2
    msr vbar_el1, x3
    
    ldp x2, x3, [x1, #SYSREG_SP_EL1]
    msr sp_el1, x2
    msr elr_el1, x3
    
    ldr x2, [x1, #SYSREG_SPSR_EL1]
    msr spsr_el1, x2
    
    /* Configure stage-2 translation (VTTBR_EL2) */
    ldr x2, [x18, #VCPU_VTTBR_OFFSET]
    msr vttbr_el2, x2
    
    /* Configure VTCR_EL2 */
    ldr x2, [x18, #VCPU_VTCR_OFFSET]
    msr vtcr_el2, x2
    
    /* Configure HCR_EL2 for guest execution */
    ldr x2, [x18, #VCPU_HCR_OFFSET]
    msr hcr_el2, x2
    isb
    
    /* Set guest context marker - CRITICAL for exception handling */
    msr tpidr_el2, x18
    
    /* Load guest PC and PSTATE for ERET */
    add x0, x18, #VCPU_REGS_OFFSET
    ldr x1, [x0, #248]      /* Guest PC */
    ldr x2, [x0, #256]      /* Guest PSTATE */
    msr elr_el2, x1
    msr spsr_el2, x2
    
    /* Load guest general purpose registers */
    ldp x2, x3, [x0, #16]
    ldp x4, x5, [x0, #32]
    ldp x6, x7, [x0, #48]
    ldp x8, x9, [x0, #64]
    ldp x10, x11, [x0, #80]
    ldp x12, x13, [x0, #96]
    ldp x14, x15, [x0, #112]
    ldp x16, x17, [x0, #128]
    ldp x18, x19, [x0, #144]
    ldp x20, x21, [x0, #160]
    ldp x22, x23, [x0, #176]
    ldp x24, x25, [x0, #192]
    ldp x26, x27, [x0, #208]
    ldp x28, x29, [x0, #224]
    ldr x30, [x0, #240]
    ldp x0, x1, [x0, #0]
    
    /* Enter guest at EL1 */
    eret
    
    /* When guest exits, execution returns to guest_sync_exit above,
     * which saves guest state and ERETSto the host */
SYM_CODE_END(hvc_kvm_vcpu_run)

/*
 * hvc_kvm_write_sysreg - Write EL2 system register
 * Input: 
 *   x1 = register ID (enum)
 *   x2 = value to write
 * Output: x0 = 0 on success
 */
SYM_CODE_START_LOCAL(hvc_kvm_write_sysreg)
    cmp x1, #EL2_SYSREG_VTCR    /* VTCR_EL2 */
    b.eq 1f
    cmp x1, #EL2_SYSREG_VBAR    /* VBAR_EL2 */
    b.eq 2f
    cmp x1, #EL2_SYSREG_HCR     /* HCR_EL2 */
    b.eq 3f
    cmp x1, #EL2_SYSREG_VTTBR   /* VTTBR_EL2 */
    b.eq 4f
    cmp x1, #EL2_SYSREG_TPIDR   /* TPIDR_EL2 */
    b.eq 5f
    
    /* Unknown register */
    mov x0, #-1
    eret
    
1:  /* VTCR_EL2 */
    msr vtcr_el2, x2
    isb
    mov x0, #0
    eret
    
2:  /* VBAR_EL2 */
    msr vbar_el2, x2
    isb
    mov x0, #0
    eret
    
3:  /* HCR_EL2 */
    msr hcr_el2, x2
    isb
    mov x0, #0
    eret
    
4:  /* VTTBR_EL2 */
    msr vttbr_el2, x2
    isb
    mov x0, #0
    eret
    
5:  /* TPIDR_EL2 */
    msr tpidr_el2, x2
    mov x0, #0
    eret
SYM_CODE_END(hvc_kvm_write_sysreg)

/*
 * hvc_kvm_read_sysreg - Read EL2 system register
 * Input: x1 = register ID
 * Output: x0 = register value
 */
SYM_CODE_START_LOCAL(hvc_kvm_read_sysreg)
    cmp x1, #EL2_SYSREG_VTCR    /* VTCR_EL2 */
    b.eq 1f
    cmp x1, #EL2_SYSREG_VBAR    /* VBAR_EL2 */
    b.eq 2f
    cmp x1, #EL2_SYSREG_HCR     /* HCR_EL2 */
    b.eq 3f
    cmp x1, #EL2_SYSREG_VTTBR   /* VTTBR_EL2 */
    b.eq 4f
    
    /* Unknown register */
    mov x0, #-1
    eret
    
1:  /* VTCR_EL2 */
    mrs x0, vtcr_el2
    eret
    
2:  /* VBAR_EL2 */
    mrs x0, vbar_el2
    eret
    
3:  /* HCR_EL2 */
    mrs x0, hcr_el2
    eret
    
4:  /* VTTBR_EL2 */
    mrs x0, vttbr_el2
    eret
SYM_CODE_END(hvc_kvm_read_sysreg)

/*
 * Data section - Per-CPU host context storage
 * 
 * Each CPU has its own dedicated storage for host context.
 * We place it in the TEXT section to ensure it remains physically 
 * contiguous with the code when copied to a specific memory region.
 * Since we copy the stub to a RWX buffer (physically contiguous),
 * this effectively becomes writable data.
 */
.align 3

/* Per-CPU host context storage */
SYM_DATA_START(__kvm_host_contexts)
    .space (MAX_CPUS * HOST_CONTEXT_SIZE)  /* 8 CPUs * 168 bytes = 1344 bytes */
SYM_DATA_END(__kvm_host_contexts)

/* End of code/data section marker */
.global __kvm_el2_stub_end
__kvm_el2_stub_end:

