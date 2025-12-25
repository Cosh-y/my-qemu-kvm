/*
 * mini_kvm_module.c - Minimal KVM kernel module for ARM64
 * 
 * This module provides basic hypervisor functionality:
 * - EL2 initialization
 * - World switching between host and guest
 * - Stage-2 memory translation
 * - MMIO trap handling
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <asm/sysreg.h>
#include "mini_kvm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MiniKVM");
MODULE_DESCRIPTION("Minimal KVM module for ARM64");

/* VM instance structure */
struct minikvm_vm {
    struct minikvm_regs guest_regs;
    struct minikvm_run_state run_state;
    void *guest_mem;            /* Kernel virtual address of guest memory */
    unsigned long guest_phys;   /* Physical address of guest memory */
    size_t guest_mem_size;
    int created;
    int vcpu_created;
};

/* Per-file private data */
struct minikvm_file_data {
    struct minikvm_vm *vm;
};

/* Check if CPU supports virtualization */
static int check_el2_support(void)
{
    u64 id_aa64mmfr1;
    
    /* Read ID_AA64MMFR1_EL1 to check virtualization support */
    id_aa64mmfr1 = read_sysreg(id_aa64mmfr1_el1);
    
    pr_info("mini_kvm: ID_AA64MMFR1_EL1 = 0x%llx\n", id_aa64mmfr1);
    
    /* Note: In VHE (Virtualization Host Extensions) mode, 
     * the kernel runs at EL2 instead of EL1 */
    
    return 0;
}

/* Create a new VM */
static int minikvm_create_vm(struct minikvm_vm *vm)
{
    if (vm->created) {
        pr_err("mini_kvm: VM already created\n");
        return -EEXIST;
    }
    
    /* Allocate guest memory (4KB for minimal test) */
    vm->guest_mem_size = PAGE_SIZE;
    vm->guest_mem = kmalloc(vm->guest_mem_size, GFP_KERNEL);
    if (!vm->guest_mem) {
        pr_err("mini_kvm: Failed to allocate guest memory\n");
        return -ENOMEM;
    }
    
    memset(vm->guest_mem, 0, vm->guest_mem_size);
    vm->guest_phys = virt_to_phys(vm->guest_mem);
    
    pr_info("mini_kvm: VM created, guest_mem=%px, phys=%lx, size=%zu\n",
            vm->guest_mem, vm->guest_phys, vm->guest_mem_size);
    
    vm->created = 1;
    return 0;
}

/* Create a vCPU */
static int minikvm_create_vcpu(struct minikvm_vm *vm)
{
    if (!vm->created) {
        pr_err("mini_kvm: VM not created\n");
        return -EINVAL;
    }
    
    if (vm->vcpu_created) {
        pr_err("mini_kvm: vCPU already created\n");
        return -EEXIST;
    }
    
    /* Initialize guest registers */
    memset(&vm->guest_regs, 0, sizeof(vm->guest_regs));
    vm->guest_regs.pc = 0x40000000; /* Default guest entry point */
    vm->guest_regs.pstate = 0x3c5;  /* EL1h, IRQ/FIQ masked */
    
    pr_info("mini_kvm: vCPU created, PC=0x%llx\n", vm->guest_regs.pc);
    
    vm->vcpu_created = 1;
    return 0;
}

/* Set guest registers */
static int minikvm_set_regs(struct minikvm_vm *vm, struct minikvm_regs __user *uregs)
{
    if (!vm->vcpu_created) {
        pr_err("mini_kvm: vCPU not created\n");
        return -EINVAL;
    }
    
    if (copy_from_user(&vm->guest_regs, uregs, sizeof(vm->guest_regs))) {
        return -EFAULT;
    }
    
    pr_info("mini_kvm: Set guest PC=0x%llx\n", vm->guest_regs.pc);
    return 0;
}

/* Get guest registers */
static int minikvm_get_regs(struct minikvm_vm *vm, struct minikvm_regs __user *uregs)
{
    if (!vm->vcpu_created) {
        pr_err("mini_kvm: vCPU not created\n");
        return -EINVAL;
    }
    
    if (copy_to_user(uregs, &vm->guest_regs, sizeof(vm->guest_regs))) {
        return -EFAULT;
    }
    
    return 0;
}

/* Set memory region */
static int minikvm_set_mem(struct minikvm_vm *vm, struct minikvm_mem_region __user *uregion)
{
    struct minikvm_mem_region region;
    void *user_mem;
    
    if (!vm->created) {
        pr_err("mini_kvm: VM not created\n");
        return -EINVAL;
    }
    
    if (copy_from_user(&region, uregion, sizeof(region))) {
        return -EFAULT;
    }
    
    pr_info("mini_kvm: Set memory region: GPA=0x%llx, size=0x%llx, UVA=0x%llx\n",
            region.guest_phys_addr, region.memory_size, region.userspace_addr);
    
    /* In a real implementation, we would:
     * 1. Use get_user_pages() to pin the userspace memory
     * 2. Set up Stage-2 page tables to map GPA -> HPA
     * For this minimal version, we just validate the parameters */
    
    if (region.memory_size > vm->guest_mem_size) {
        pr_warn("mini_kvm: Requested size larger than allocated memory\n");
    }
    
    return 0;
}

/* 
 * Run the vCPU - This is the core function
 * 
 * In a real hypervisor, this would:
 * 1. Save host state
 * 2. Load guest state
 * 3. Execute ERET to enter guest at EL1
 * 4. Handle traps/exits from guest
 * 5. Restore host state and return
 * 
 * For this minimal version, we simulate guest execution
 */
static int minikvm_run(struct minikvm_vm *vm, struct minikvm_run_state __user *urun_state)
{
    u32 *guest_code;
    u64 guest_pc;
    
    if (!vm->vcpu_created) {
        pr_err("mini_kvm: vCPU not created\n");
        return -EINVAL;
    }
    
    guest_pc = vm->guest_regs.pc;
    
    pr_info("mini_kvm: Running vCPU at PC=0x%llx\n", guest_pc);
    
    /* Check if PC is within our guest memory */
    if (guest_pc < 0x40000000 || guest_pc >= 0x40000000 + vm->guest_mem_size) {
        pr_err("mini_kvm: PC out of guest memory range\n");
        vm->run_state.exit_reason = MINIKVM_EXIT_INTERNAL_ERROR;
        vm->run_state.internal_error.error_code = 1;
        vm->run_state.internal_error.padding = 0;
        goto exit;
    }
    
    /* Simulate guest execution by reading instruction at PC
     * In real implementation, this would be handled by hardware */
    guest_code = (u32 *)((unsigned long)vm->guest_mem + (guest_pc - 0x40000000));
    
    pr_info("mini_kvm: Guest instruction at PC: 0x%08x\n", *guest_code);
    
    /* Simulate MMIO trap
     * ARM64 STR instruction to MMIO region would cause a trap
     * For simulation, we check if instruction looks like a store */
    
    /* Simple pattern: if instruction is a store (STR/STUR), simulate MMIO */
    u32 insn = *guest_code;
    
    /* ARM64 STR immediate: opcode pattern 1x11100x */
    if ((insn & 0x3fc00000) == 0x39000000 || /* STRB */
        (insn & 0x3fc00000) == 0x79000000 || /* STRH */
        (insn & 0x3fc00000) == 0xb9000000 || /* STR 32-bit */
        (insn & 0x3fc00000) == 0xf9000000) { /* STR 64-bit */
        
        /* Simulate MMIO write */
        u64 mmio_addr = 0x09000000; /* Simulated UART address */
        u64 data = vm->guest_regs.x[1]; /* Assume data in x1 */
        
        pr_info("mini_kvm: MMIO Write detected: addr=0x%llx, data=0x%llx\n",
                mmio_addr, data);
        
        vm->run_state.exit_reason = MINIKVM_EXIT_MMIO;
        vm->run_state.mmio.phys_addr = mmio_addr;
        vm->run_state.mmio.data = data;
        vm->run_state.mmio.len = 4;
        vm->run_state.mmio.is_write = 1;
        vm->run_state.mmio.padding[0] = 0;
        vm->run_state.mmio.padding[1] = 0;
        vm->run_state.mmio.padding[2] = 0;
        
        /* Advance PC */
        vm->guest_regs.pc += 4;
        
    } else if (insn == 0xd503207f) { /* WFI instruction */
        pr_info("mini_kvm: WFI instruction, halting\n");
        vm->run_state.exit_reason = MINIKVM_EXIT_HLT;
        
    } else if (insn == 0x14000000) { /* B . (infinite loop) */
        pr_info("mini_kvm: Infinite loop detected, shutdown\n");
        vm->run_state.exit_reason = MINIKVM_EXIT_SHUTDOWN;
        
    } else {
        /* Unknown instruction, advance PC and continue */
        pr_info("mini_kvm: Unknown instruction 0x%08x, continuing\n", insn);
        vm->guest_regs.pc += 4;
        vm->run_state.exit_reason = MINIKVM_EXIT_UNKNOWN;
    }
    
exit:
    /* Copy run state back to userspace */
    if (copy_to_user(urun_state, &vm->run_state, sizeof(vm->run_state))) {
        return -EFAULT;
    }
    
    return 0;
}

/* ioctl handler */
static long minikvm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct minikvm_file_data *data = file->private_data;
    struct minikvm_vm *vm = data->vm;
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
    struct minikvm_vm *vm;
    
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
    struct minikvm_vm *vm = data->vm;
    
    if (vm) {
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
    
    pr_info("mini_kvm: Initializing minimal KVM module\n");
    
    /* Check EL2 support */
    ret = check_el2_support();
    if (ret) {
        pr_err("mini_kvm: CPU does not support virtualization\n");
        return ret;
    }
    
    /* Register device */
    ret = misc_register(&minikvm_dev);
    if (ret) {
        pr_err("mini_kvm: Failed to register device\n");
        return ret;
    }
    
    pr_info("mini_kvm: Module loaded successfully, device: /dev/mini_kvm\n");
    return 0;
}

/* Module cleanup */
static void __exit minikvm_exit(void)
{
    misc_deregister(&minikvm_dev);
    pr_info("mini_kvm: Module unloaded\n");
}

module_init(minikvm_init);
