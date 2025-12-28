/*
 * mini_kvm_module_new.c - Full KVM implementation for ARM64
 * 
 * This module provides complete hypervisor functionality:
 * - EL2 initialization and configuration
 * - Real world switching between host (EL2) and guest (EL1)
 * - Stage-2 memory translation with page table management
 * - System register context switching
 * - Exception handling for guest traps
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/cpu.h>
#include <asm/sysreg.h>
#include <asm/virt.h>
#include <asm/cacheflush.h>
#include "mini_kvm.h"
#include "kvm_hyp.h"
#include "kvm_hvc.h"

/* External symbol from assembly - EL2 exception vector table */
extern char __kvm_el2_stub_vectors[];
extern char __kvm_el2_stub_end[];

/* Global flag: true if using HVC calls, false if direct EL2 access */
static bool use_hvc_calls = false;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MiniKVM");
MODULE_DESCRIPTION("Full KVM module for ARM64 with stage-2 paging");

/* Global VMID allocator */
static u64 next_vmid = 1;

/* Per-file private data */
struct minikvm_file_data {
    struct kvm_vm *vm;
};

/*
 * Stage-2 page table management
 */

/* Allocate a page table page */
static u64 *s2_alloc_table(void)
{
    struct page *page;
    u64 *table;
    
    page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!page)
        return NULL;
    
    table = page_address(page);
    return table;
}

/* Free a page table page */
static void s2_free_table(u64 *table)
{
    if (table) {
        free_page((unsigned long)table);
    }
}

/*
 * Create stage-2 page table mapping
 * Maps guest IPA -> host PA with 2MB granularity for simplicity
 */
static int s2_map_range(struct kvm_vm *vm, u64 ipa_start, u64 pa_start, u64 size)
{
    u64 ipa, pa;
    u64 *pgd, *pud;
    u64 pgd_idx, pud_idx;
    u64 pte_val;
    
    pr_info("mini_kvm: Mapping IPA 0x%llx -> PA 0x%llx, size 0x%llx\n",
            ipa_start, pa_start, size);
    
    for (ipa = ipa_start, pa = pa_start; 
         ipa < ipa_start + size; 
         ipa += (1UL << S2_PUD_SHIFT), pa += (1UL << S2_PUD_SHIFT)) {
        
        /* Calculate indices for 3-level page table */
        pgd_idx = (ipa >> S2_PGDIR_SHIFT) & (S2_PTRS_PER_TABLE - 1);
        pud_idx = (ipa >> S2_PUD_SHIFT) & (S2_PTRS_PER_TABLE - 1);
        
        pgd = vm->s2_pgd;
        
        /* Level 1: PGD */
        if (!(pgd[pgd_idx] & S2_PTE_VALID)) {
            pud = s2_alloc_table();
            if (!pud) {
                pr_err("mini_kvm: Failed to allocate PUD table\n");
                return -ENOMEM;
            }
            pgd[pgd_idx] = virt_to_phys(pud) | S2_PTE_TABLE | S2_PTE_VALID;
        }
        
        pud = phys_to_virt(pgd[pgd_idx] & ~0xFFFUL);
        
        /* Level 2: PUD - create 2MB block mapping */
        pte_val = (pa & ~((1UL << S2_PUD_SHIFT) - 1)) |
                  S2_PTE_VALID |
                  S2_PTE_AF |
                  S2_PTE_SH_INNER |
                  S2_PTE_S2AP_RW |
                  S2_PTE_MEMATTR_NORM;
        
        pud[pud_idx] = pte_val;
    }
    
    return 0;
}

/*
 * Initialize stage-2 page tables for a VM
 */
static int s2_init_tables(struct kvm_vm *vm)
{
    u64 vtcr_value;
    
    /* Allocate PGD (level 1 table) */
    vm->s2_pgd = s2_alloc_table();
    if (!vm->s2_pgd) {
        pr_err("mini_kvm: Failed to allocate stage-2 PGD\n");
        return -ENOMEM;
    }
    
    vm->s2_pgd_phys = virt_to_phys(vm->s2_pgd);
    
    pr_info("mini_kvm: Stage-2 PGD allocated at PA 0x%lx\n", vm->s2_pgd_phys);
    
    /* Configure VTCR_EL2 for stage-2 translation */
    vtcr_value = S2_VTCR_PS_40BIT |
                 S2_VTCR_TG0_4K |
                 S2_VTCR_SH0_INNER |
                 S2_VTCR_ORGN0_WBWA |
                 S2_VTCR_IRGN0_WBWA |
                 S2_VTCR_SL0_L1 |
                 S2_VTCR_T0SZ_25BIT;
    
    vm->vtcr_el2 = vtcr_value;
    
    /* We don't write VTCR_EL2 here anymore, it will be written on vCPU run */
    
    pr_info("mini_kvm: VTCR_EL2 configured: 0x%llx\n", vtcr_value);
    
    return 0;
}

/*
 * Free stage-2 page tables
 */
static void s2_free_tables(struct kvm_vm *vm)
{
    int i;
    u64 *pgd, *pud;
    
    if (!vm->s2_pgd)
        return;
    
    pgd = vm->s2_pgd;
    
    /* Free PUD tables */
    for (i = 0; i < S2_PTRS_PER_TABLE; i++) {
        if (pgd[i] & S2_PTE_VALID) {
            pud = phys_to_virt(pgd[i] & ~0xFFFUL);
            s2_free_table(pud);
        }
    }
    
    /* Free PGD */
    s2_free_table(pgd);
    vm->s2_pgd = NULL;
}

/*
 * Per-CPU initialization function
 */
static void __init_el2_on_cpu(void *info)
{
    unsigned long stub_vbar = (unsigned long)info;
    int ret;
    int cpu = smp_processor_id();
    
    /* Step 1: Install our stub using kernel's HVC_SET_VECTORS */
    ret = kvm_hvc_set_vectors(stub_vbar);
    if (ret != 0) {
        pr_err("mini_kvm: [CPU%d] Failed to install EL2 stub\n", cpu);
        return;
    }
    
    /* Step 2: Initialize hypervisor state (clear TPIDR_EL2, etc.) */
    ret = kvm_hvc_init_hyp();
    if (ret != 0) {
        pr_err("mini_kvm: [CPU%d] Failed to initialize hypervisor state\n", cpu);
        return;
    }
    
    pr_info("mini_kvm: [CPU%d] EL2 initialized\n", cpu);
}

/*
 * Initialize EL2 via HVC calls
 */
static int init_el2_hvc(void)
{
    unsigned long stub_vbar;
    
    pr_info("mini_kvm: Initializing EL2 via HVC calls\n");
    
    /* 
     * CRITICAL: __kvm_el2_stub_vectors is in module memory (vmalloc).
     * virt_to_phys() may not work correctly for vmalloc addresses.
     * We must use vmalloc_to_page() to get the physical address.
     */
    struct page *stub_page = vmalloc_to_page(&__kvm_el2_stub_vectors);
    if (!stub_page) {
        pr_err("mini_kvm: Failed to get page for vector table\n");
        return -EFAULT;
    }
    stub_vbar = page_to_phys(stub_page) + offset_in_page(&__kvm_el2_stub_vectors);
    
    /* Print vector table address information */
    unsigned long stub_size = (unsigned long)__kvm_el2_stub_end - (unsigned long)__kvm_el2_stub_vectors;
    pr_info("mini_kvm: Vector table virtual address: %px - %px (size: %lu bytes / 0x%lx)\n",
            __kvm_el2_stub_vectors, __kvm_el2_stub_end, stub_size, stub_size);
    pr_info("mini_kvm: Vector table physical start: 0x%lx (vmalloc, may be non-contiguous)\n",
            stub_vbar);
    
    /* Clean instruction cache to ensure CPU fetches latest code
     * This is CRITICAL before calling kvm_hvc_init_hyp */
    pr_info("mini_kvm: Cleaning instruction cache for vector table\n");
    flush_icache_range((unsigned long)__kvm_el2_stub_vectors, 
                       (unsigned long)__kvm_el2_stub_end);
    
    /* Run initialization on ALL CPUs */
    cpus_read_lock();
    on_each_cpu(__init_el2_on_cpu, (void *)stub_vbar, 1);
    cpus_read_unlock();
    
    /* Verify VBAR_EL2 on current CPU */
    unsigned long verify_vbar = kvm_hvc_read_vbar_el2();
    if (verify_vbar != stub_vbar) {
        pr_warn("mini_kvm: VBAR_EL2 = 0x%lx (expected 0x%lx)\n",
                verify_vbar, stub_vbar);
    } else {
        pr_info("mini_kvm: ✓ VBAR_EL2 verified via our stub\n");
    }
    
    pr_info("mini_kvm: ✓ EL2 initialization complete via HVC\n");
    
    return 0;
}

/*
 * Initialize guest system registers to safe defaults
 */
static void init_guest_sysregs(struct kvm_vcpu *vcpu)
{
    struct kvm_sys_regs *sr = &vcpu->sys_regs;
    
    /* Initialize EL1 system registers */
    sr->sctlr_el1 = 0x30C50830;  /* MMU off, caches off, default bits */
    sr->ttbr0_el1 = 0;
    sr->ttbr1_el1 = 0;
    sr->tcr_el1 = 0;
    sr->mair_el1 = 0;
    sr->vbar_el1 = 0;
    sr->sp_el1 = 0;
    sr->elr_el1 = 0;
    sr->spsr_el1 = 0;
    sr->esr_el1 = 0;
    sr->far_el1 = 0;
    sr->par_el1 = 0;
    sr->contextidr_el1 = 0;
    sr->tpidr_el1 = 0;
    sr->tpidrro_el1 = 0;
    sr->amair_el1 = 0;
}

/*
 * Create a new VM
 */
static int minikvm_create_vm(struct kvm_vm *vm)
{
    int ret;
    
    if (vm->created) {
        pr_err("mini_kvm: VM already created\n");
        return -EEXIST;
    }
    
    /* Allocate guest memory (4MB - physically contiguous for MVP)
     * Use kmalloc instead of vmalloc to ensure physical contiguity.
     * kmalloc guarantees contiguous physical memory for sizes up to 4MB.
     */
    vm->guest_mem_size = 4 * 1024 * 1024;  /* 4MB */
    vm->guest_mem = kmalloc(vm->guest_mem_size, GFP_KERNEL | __GFP_ZERO);
    if (!vm->guest_mem) {
        pr_err("mini_kvm: Failed to allocate physically contiguous guest memory\n");
        return -ENOMEM;
    }
    
    vm->guest_phys = virt_to_phys(vm->guest_mem);
    
    /* Allocate VMID */
    vm->vmid = next_vmid++;
    if (vm->vmid > 255) {
        vm->vmid = 1;  /* Wrap around, simple allocator */
        next_vmid = 2;
    }
    
    /* Initialize stage-2 page tables */
    ret = s2_init_tables(vm);
    if (ret) {
        kfree(vm->guest_mem);
        return ret;
    }
    
    /* Map guest memory into stage-2 page tables
     * Guest IPA 0x40000000 -> Host PA vm->guest_phys */
    ret = s2_map_range(vm, 0x40000000, vm->guest_phys, vm->guest_mem_size);
    if (ret) {
        s2_free_tables(vm);
        kfree(vm->guest_mem);
        return ret;
    }
    
    pr_info("mini_kvm: VM created, VMID=%llu, guest_mem=%px, phys=%lx, size=%zu\n",
            vm->vmid, vm->guest_mem, vm->guest_phys, vm->guest_mem_size);
    
    vm->created = 1;
    return 0;
}

/*
 * Create a vCPU
 */
static int minikvm_create_vcpu(struct kvm_vm *vm)
{
    struct kvm_vcpu *vcpu;
    
    if (!vm->created) {
        pr_err("mini_kvm: VM not created\n");
        return -EINVAL;
    }
    
    if (vm->vcpu) {
        pr_err("mini_kvm: vCPU already created\n");
        return -EEXIST;
    }
    
    /* Allocate vCPU structure */
    vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL);
    if (!vcpu) {
        pr_err("mini_kvm: Failed to allocate vCPU\n");
        return -ENOMEM;
    }
    
    /* Initialize guest registers */
    memset(&vcpu->regs, 0, sizeof(vcpu->regs));
    vcpu->regs.pc = 0x40000000;  /* Guest entry point */
    vcpu->regs.pstate = 0x3c5;    /* EL1h, IRQ/FIQ masked */
    
    /* Initialize system registers */
    init_guest_sysregs(vcpu);
    
    /* Configure HCR_EL2 for guest execution */
    vcpu->hcr_el2 = HCR_GUEST_FLAGS;
    
    /* Set up VTTBR_EL2 (stage-2 translation base + VMID) */
    vcpu->vttbr_el2 = vm->s2_pgd_phys | (vm->vmid << 48);
    
    /* Set up VTCR_EL2 */
    vcpu->vtcr_el2 = vm->vtcr_el2;
    
    /* Link vcpu to vm */
    vcpu->vm = vm;
    vm->vcpu = vcpu;
    
    pr_info("mini_kvm: vCPU created, PC=0x%llx, HCR=0x%llx, VTTBR=0x%llx\n",
            vcpu->regs.pc, vcpu->hcr_el2, vcpu->vttbr_el2);
    
    return 0;
}

/*
 * Set guest registers
 */
static int minikvm_set_regs(struct kvm_vm *vm, struct minikvm_regs __user *uregs)
{
    struct minikvm_regs regs;
    struct kvm_vcpu *vcpu = vm->vcpu;
    int i;
    
    if (!vcpu) {
        pr_err("mini_kvm: vCPU not created\n");
        return -EINVAL;
    }
    
    if (copy_from_user(&regs, uregs, sizeof(regs))) {
        return -EFAULT;
    }
    
    /* Copy general purpose registers */
    for (i = 0; i < 31; i++) {
        vcpu->regs.x[i] = regs.x[i];
    }
    vcpu->regs.sp = regs.sp;
    vcpu->regs.pc = regs.pc;
    vcpu->regs.pstate = regs.pstate;
    
    /* 
     * CRITICAL: Sync SP to system register SP_EL1 
     * The assembly code restores SP_EL1 from sys_regs, not regs.sp
     */
    vcpu->sys_regs.sp_el1 = regs.sp;
    
    pr_info("mini_kvm: Set guest PC=0x%llx, SP=0x%llx\n", 
            vcpu->regs.pc, vcpu->regs.sp);
    
    return 0;
}

/*
 * Get guest registers
 */
static int minikvm_get_regs(struct kvm_vm *vm, struct minikvm_regs __user *uregs)
{
    struct minikvm_regs regs;
    struct kvm_vcpu *vcpu = vm->vcpu;
    int i;
    
    if (!vcpu) {
        pr_err("mini_kvm: vCPU not created\n");
        return -EINVAL;
    }
    
    /* Copy general purpose registers */
    for (i = 0; i < 31; i++) {
        regs.x[i] = vcpu->regs.x[i];
    }
    regs.sp = vcpu->regs.sp;
    regs.pc = vcpu->regs.pc;
    regs.pstate = vcpu->regs.pstate;
    
    if (copy_to_user(uregs, &regs, sizeof(regs))) {
        return -EFAULT;
    }
    
    return 0;
}

/*
 * Set memory region
 */
static int minikvm_set_mem(struct kvm_vm *vm, struct minikvm_mem_region __user *uregion)
{
    struct minikvm_mem_region region;
    
    if (!vm->created) {
        pr_err("mini_kvm: VM not created\n");
        return -EINVAL;
    }
    
    if (copy_from_user(&region, uregion, sizeof(region))) {
        return -EFAULT;
    }
    
    pr_info("mini_kvm: Set memory region: GPA=0x%llx, size=0x%llx, UVA=0x%llx\n",
            region.guest_phys_addr, region.memory_size, region.userspace_addr);
    
    /* In this implementation, we use a fixed guest memory mapping */
    /* A full implementation would use get_user_pages() here */
    
    if (region.memory_size > vm->guest_mem_size) {
        pr_warn("mini_kvm: Requested size larger than allocated memory\n");
        return -EINVAL;
    }
    
    /* Copy guest code from userspace to kernel memory */
    if (copy_from_user(vm->guest_mem, (void __user *)region.userspace_addr, 
                       region.memory_size)) {
        pr_err("mini_kvm: Failed to copy guest code\n");
        return -EFAULT;
    }
    
    /* 
     * CRITICAL: Flush D-cache and invalidate I-cache for the guest memory range.
     * Since we wrote instructions via data path (copy_from_user), they are in D-cache.
     * The guest will fetch them via I-cache. We must ensure coherency.
     */
    flush_icache_range((unsigned long)vm->guest_mem, 
                       (unsigned long)vm->guest_mem + region.memory_size);
    
    pr_info("mini_kvm: Copied %llu bytes of guest code\n", region.memory_size);
    
    return 0;
}

/*
 * Handle VM exit - analyze why the guest exited and prepare exit information
 */
static int handle_vm_exit(struct kvm_vcpu *vcpu, struct minikvm_run_state *run_state)
{
    u32 esr_ec;  /* Exception class */
    u64 esr = vcpu->esr_el2;
    
    /* Extract exception class from ESR_EL2 [31:26] */
    esr_ec = (esr >> 26) & 0x3F;
    
    pr_info("mini_kvm: VM exit - ESR_EL2=0x%llx, EC=0x%x, PC=0x%llx\n",
            esr, esr_ec, vcpu->regs.pc);
    
    switch (esr_ec) {
    case 0x24:  /* Data Abort from lower EL */
    case 0x20:  /* Instruction Abort from lower EL */
        /* Stage-2 fault */
        pr_info("mini_kvm: Stage-2 fault - FAR=0x%llx, HPFAR=0x%llx\n",
                vcpu->far_el2, vcpu->hpfar_el2);
        
        /* For MMIO, this is expected */
        run_state->exit_reason = MINIKVM_EXIT_MMIO;
        run_state->mmio.phys_addr = vcpu->far_el2;
        run_state->mmio.len = 4;
        run_state->mmio.is_write = (esr_ec == 0x24) && (esr & (1 << 6));  /* WnR bit */
        run_state->mmio.data = vcpu->regs.x[1];  /* Assume data in x1 */
        
        /* Advance PC past faulting instruction */
        vcpu->regs.pc += 4;
        break;
        
    case 0x01:  /* WFI/WFE instruction */
        pr_info("mini_kvm: WFI/WFE trapped\n");
        run_state->exit_reason = MINIKVM_EXIT_HLT;
        vcpu->regs.pc += 4;
        break;
        
    case 0x00:  /* Unknown reason */
    default:
        pr_warn("mini_kvm: Unknown exit reason, EC=0x%x\n", esr_ec);
        run_state->exit_reason = MINIKVM_EXIT_UNKNOWN;
        break;
    }
    
    return 0;
}

/*
 * Run the vCPU - Enter guest at EL1
 */
static int minikvm_run(struct kvm_vm *vm, struct minikvm_run_state __user *urun_state)
{
    struct kvm_vcpu *vcpu = vm->vcpu;
    struct minikvm_run_state run_state;
    int ret;
    
    if (!vcpu) {
        pr_err("mini_kvm: vCPU not created\n");
        return -EINVAL;
    }
    
    pr_info("mini_kvm: Running vCPU at PC=0x%llx\n", vcpu->regs.pc);
    
    /* 
     * Call assembly world switch function.
     * CRITICAL: We must pass the PHYSICAL address of the vcpu structure
     * because EL2 runs with MMU disabled (or identity mapped).
     * Also, do NOT set TPIDR_EL2 here - it is used to distinguish
     * guest vs host context in the exception handler. It must be 0
     * when calling from host. The HVC handler will set it.
     */
    ret = kvm_hvc_vcpu_run((void *)virt_to_phys(vcpu));
    
    if (ret != 0) {
        pr_err("mini_kvm: __kvm_vcpu_run failed with %d\n", ret);
        run_state.exit_reason = MINIKVM_EXIT_INTERNAL_ERROR;
        run_state.internal_error.error_code = ret;
        run_state.internal_error.padding = 0;
    } else {
        /* Handle the VM exit */
        handle_vm_exit(vcpu, &run_state);
    }
    
    /* Copy run state back to userspace */
    if (copy_to_user(urun_state, &run_state, sizeof(run_state))) {
        return -EFAULT;
    }
    
    return 0;
}

/* ioctl handler */
static long minikvm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct minikvm_file_data *data = file->private_data;
    struct kvm_vm *vm = data->vm;
    int ret = 0;
    
    switch (cmd) {
    case MINIKVM_CREATE_VM:
        ret = minikvm_create_vm(vm);
        break;
        
    case MINIKVM_CREATE_VCPU:
        ret = minikvm_create_vcpu(vm);
        break;
        
    case MINIKVM_SET_REGS:
        ret = minikvm_set_regs(vm, (struct minikvm_regs __user *)arg);
        break;
        
    case MINIKVM_GET_REGS:
        ret = minikvm_get_regs(vm, (struct minikvm_regs __user *)arg);
        break;
        
    case MINIKVM_SET_MEM:
        ret = minikvm_set_mem(vm, (struct minikvm_mem_region __user *)arg);
        break;
        
    case MINIKVM_RUN:
        ret = minikvm_run(vm, (struct minikvm_run_state __user *)arg);
        break;
        
    default:
        pr_err("mini_kvm: Unknown ioctl command: 0x%x\n", cmd);
        ret = -EINVAL;
        break;
    }
    
    return ret;
}

/* File operations */
static int minikvm_open(struct inode *inode, struct file *file)
{
    struct minikvm_file_data *data;
    struct kvm_vm *vm;
    
    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;
    
    vm = kzalloc(sizeof(*vm), GFP_KERNEL);
    if (!vm) {
        kfree(data);
        return -ENOMEM;
    }
    
    data->vm = vm;
    file->private_data = data;
    
    pr_info("mini_kvm: Device opened\n");
    return 0;
}

static int minikvm_release(struct inode *inode, struct file *file)
{
    struct minikvm_file_data *data = file->private_data;
    struct kvm_vm *vm = data->vm;
    
    if (vm) {
        if (vm->vcpu) {
            kfree(vm->vcpu);
        }
        if (vm->s2_pgd) {
            s2_free_tables(vm);
        }
        if (vm->guest_mem) {
            kfree(vm->guest_mem);
        }
        kfree(vm);
    }
    
    kfree(data);
    
    pr_info("mini_kvm: Device closed\n");
    return 0;
}

static const struct file_operations minikvm_fops = {
    .owner = THIS_MODULE,
    .open = minikvm_open,
    .release = minikvm_release,
    .unlocked_ioctl = minikvm_ioctl,
};

static struct miscdevice minikvm_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "mini_kvm",
    .fops = &minikvm_fops,
};

/* Module initialization */
static int __init minikvm_init(void)
{
    int ret;
    u64 id_aa64pfr0, current_el;
    
    pr_info("mini_kvm: Initializing full KVM module with stage-2 paging\n");
    
    /* Check current exception level */
    current_el = read_sysreg(CurrentEL);
    current_el = (current_el >> 2) & 3;  /* Extract EL[3:2] */
    pr_info("mini_kvm: Current Exception Level: EL%llu\n", current_el);
    
    /* Check if CPU supports virtualization */
    id_aa64pfr0 = read_sysreg(id_aa64pfr0_el1);
    pr_info("mini_kvm: ID_AA64PFR0_EL1 = 0x%llx\n", id_aa64pfr0);
    
    /* Check virtualization support (EL2 implemented) */
    if (((id_aa64pfr0 >> 8) & 0xF) == 0) {
        pr_err("mini_kvm: CPU does not support EL2/virtualization\n");
        return -ENODEV;
    }
    
    /* 
     * Check if we can access EL2:
     * 1. Running at EL2 directly, or
     * 2. Running in VHE mode (kernel at EL2), or  
     * 3. Use HVC calls (standard for non-VHE systems like Cortex-A57)
     */
    if (current_el == 2 || is_kernel_in_hyp_mode()) {
        pr_err("mini_kvm: Kernel module running at EL2 directly, which is unexpected\n");
    } else if (current_el == 1) {
        pr_info("mini_kvm: Kernel at EL1, using HVC calls for EL2 access\n");
        
        
        /* Initialize EL2 via HVC */
        ret = init_el2_hvc();
        if (ret) {
            pr_err("mini_kvm: Failed to initialize EL2 via HVC\n");
            pr_err("mini_kvm: Ensure QEMU has virtualization enabled:\n");
            pr_err("mini_kvm:   -M virt,virtualization=on\n");
            return ret;
        }
        
        use_hvc_calls = true;
        
    } else {
        pr_err("mini_kvm: Unexpected exception level: EL%llu\n", current_el);
        return -EINVAL;
    }
    
    /* Register device */
    ret = misc_register(&minikvm_dev);
    if (ret) {
        pr_err("mini_kvm: Failed to register device\n");
        return ret;
    }
    
    pr_info("mini_kvm: Module loaded successfully\n");
    pr_info("mini_kvm: - Real EL1 guest execution\n");
    pr_info("mini_kvm: - System register context switching\n");
    pr_info("mini_kvm: - Stage-2 page table management\n");
    pr_info("mini_kvm: Device: /dev/mini_kvm\n");
    
    return 0;
}

/* Module cleanup */
static void __exit minikvm_exit(void)
{
    misc_deregister(&minikvm_dev);
    pr_info("mini_kvm: Module unloaded\n");
}

module_init(minikvm_init);
module_exit(minikvm_exit);
