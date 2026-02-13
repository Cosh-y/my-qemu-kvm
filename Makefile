# Mini KVM/QEMU Makefile - Multi-Architecture Support
# Set ARCH environment variable to choose architecture:
#   make ARCH=arm64   (default)
#   make ARCH=x86_64

# Architecture selection (default: arm64)
ARCH ?= x86_64

# Configuration
LINUX_DIR ?= /home/harry/Documents/chy/linux-6.18.5
KDIR := $(LINUX_DIR)

MOUNT_POINT := /tmp/mykvm_rootfs
DEPLOY_ROOT := $(MOUNT_POINT)/root/mykvm

CARGO := cargo

# Architecture-specific configuration
ifeq ($(ARCH),x86_64)
    # x86_64 configuration
    CROSS_COMPILE :=
    CC := gcc
    AS := as
    OBJCOPY := objcopy
    
    KERNEL := $(LINUX_DIR)/arch/x86/boot/bzImage
    ROOTFS ?= /home/harry/Documents/chy/busybox-1.36.1/disk-x86.img
    
    QEMU := qemu-system-x86_64
    QEMU_FLAGS := -machine q35 \
                  -cpu host -enable-kvm \
                  -m 512M \
                  -nographic \
                  -kernel $(KERNEL) \
                  -append "root=/dev/vda1 console=ttyS0 rw" \
                  -drive file=$(ROOTFS),format=raw,id=hd0,if=virtio
    
    CARGO_TARGET := x86_64-unknown-linux-gnu
    KERNEL_ARCH := x86_64
    RKVM_DIR := rkvm-x86
    GUEST_DIR := guest-x86
else
    # arm64 configuration (default)
    CROSS_COMPILE ?= aarch64-linux-gnu-
    CC := $(CROSS_COMPILE)gcc
    AS := $(CROSS_COMPILE)as
    OBJCOPY := $(CROSS_COMPILE)objcopy
    
    KERNEL := $(LINUX_DIR)/arch/arm64/boot/Image
    ROOTFS ?= /home/harry/Documents/chy/busybox-1.36.1/disk.img
    
    QEMU := qemu-system-aarch64
    QEMU_FLAGS := -machine virt,gic-version=3,virtualization=on \
                  -cpu cortex-a57 \
                  -m 512M \
                  -nographic \
                  -kernel $(KERNEL) \
                  -append "root=/dev/vda1 console=ttyAMA0 rw kvm-arm.mode=none" \
                  -drive file=$(ROOTFS),format=raw,id=hd0,if=virtio
    
    CARGO_TARGET := aarch64-unknown-linux-gnu
    KERNEL_ARCH := arm64
    RKVM_DIR := rkvm
    GUEST_DIR := guest
endif

.PHONY: all clean kvm rkvm qemu guest deploy mount umount run info

all: info kvm rkvm qemu guest

# Display build configuration
info:
	@echo "========================================"
	@echo "Building for architecture: $(ARCH)"
	@echo "CROSS_COMPILE: $(CROSS_COMPILE)"
	@echo "KERNEL_ARCH: $(KERNEL_ARCH)"
	@echo "CARGO_TARGET: $(CARGO_TARGET)"
	@echo "RKVM_DIR: $(RKVM_DIR)"
	@echo "GUEST_DIR: $(GUEST_DIR)"
	@echo "========================================"

# Build C kernel module
kvm:
ifeq ($(ARCH),arm64)
	$(MAKE) -C $(KDIR) M=$(PWD)/kvm LLVM=1 ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules
else
	@echo "Note: C kernel module (kvm/) only supports ARM64"
endif

# Build Rust kernel module
rkvm:
	$(MAKE) -C $(RKVM_DIR) LINUX_DIR=$(LINUX_DIR) CROSS_COMPILE=$(CROSS_COMPILE) build

# Build Rust VMM
qemu:
ifeq ($(ARCH),arm64)
	cd qemu && $(CARGO) build --features arch-arm64 --release --target $(CARGO_TARGET)
else
	cd qemu && $(CARGO) build --features arch-x86 --release --target $(CARGO_TARGET)
endif

# Build guest binary
guest: $(GUEST_DIR)/guest.bin

ifeq ($(ARCH),x86_64)
# x86_64 guest build rules
guest-x86/guest.o: guest-x86/guest.S
	$(AS) -m64 -o guest-x86/guest.o guest-x86/guest.S

guest-x86/guest.bin: guest-x86/guest.o
	$(OBJCOPY) -O binary guest-x86/guest.o guest-x86/guest.bin
else
# arm64 guest build rules
guest/guest.o: guest/guest.S
	$(AS) -o guest/guest.o guest/guest.S

guest/guest.bin: guest/guest.o
	$(OBJCOPY) -O binary guest/guest.o guest/guest.bin
endif

# Explicit architecture-specific targets
guest-arm64:
	$(MAKE) ARCH=arm64 guest

guest-x86:
	$(MAKE) ARCH=x86_64 guest

rkvm-arm64:
	$(MAKE) ARCH=arm64 rkvm

rkvm-x86:
	$(MAKE) ARCH=x86_64 rkvm

# Mount rootfs
mount:
	@mkdir -p $(MOUNT_POINT)
	@mountpoint -q $(MOUNT_POINT) || sudo mount -o loop,offset=1048576 $(ROOTFS) $(MOUNT_POINT)

# Unmount rootfs
umount:
	@mountpoint -q $(MOUNT_POINT) && sudo umount $(MOUNT_POINT) || true

# Deploy files to rootfs
deploy: all mount
	@echo "Deploying for $(ARCH)..."
	@sudo mkdir -p $(DEPLOY_ROOT)/kvm $(DEPLOY_ROOT)/rkvm $(DEPLOY_ROOT)/qemu $(DEPLOY_ROOT)/guest
ifeq ($(ARCH),arm64)
	@sudo cp kvm/mini_kvm.ko $(DEPLOY_ROOT)/kvm/ 2>/dev/null || echo "Skipping kvm (not built)"
endif
	@sudo cp $(RKVM_DIR)/*.ko $(DEPLOY_ROOT)/rkvm/ 2>/dev/null || echo "Warning: rkvm module not found"
	@sudo cp qemu/target/$(CARGO_TARGET)/release/mini-qemu $(DEPLOY_ROOT)/qemu/ 2>/dev/null || echo "Warning: mini-qemu not found"
	@sudo cp $(GUEST_DIR)/guest.bin $(DEPLOY_ROOT)/guest/ 2>/dev/null || echo "Warning: guest.bin not found"
	@sync
	@$(MAKE) umount
	@echo "Deployment complete for $(ARCH)"

# Run QEMU
run:
	@echo "Starting QEMU for $(ARCH)..."
	$(QEMU) $(QEMU_FLAGS)

# Clean
clean:
	@echo "Cleaning for $(ARCH)..."
	@$(MAKE) -C $(KDIR) M=$(PWD)/kvm ARCH=$(KERNEL_ARCH) clean 2>/dev/null || true
	@$(MAKE) -C $(RKVM_DIR) clean 2>/dev/null || true
	@cd qemu && $(CARGO) clean
	@rm -f $(GUEST_DIR)/guest.o $(GUEST_DIR)/guest.bin
	@rm -f kvm/*.o kvm/*.ko kvm/*.mod kvm/*.mod.c kvm/.*.cmd kvm/Module.symvers kvm/modules.order
	@rm -rf kvm/.tmp_versions
	@rm -f rkvm/*.o rkvm/*.ko rkvm/*.mod rkvm/*.mod.c rkvm/.*.cmd rkvm/Module.symvers rkvm/modules.order
	@rm -f rkvm-x86/*.o rkvm-x86/*.ko rkvm-x86/*.mod rkvm-x86/*.mod.c rkvm-x86/.*.cmd rkvm-x86/Module.symvers rkvm-x86/modules.order
	@rm -f guest/*.o guest/*.bin guest-x86/*.o guest-x86/*.bin
	@echo "Clean complete"

# Clean all architectures
clean-all:
	@echo "Cleaning all architectures..."
	@$(MAKE) ARCH=arm64 clean
	@$(MAKE) ARCH=x86_64 clean
	@echo "Clean-all complete"

# Help target
help:
	@echo "Mini KVM/QEMU Makefile - Multi-Architecture Support"
	@echo ""
	@echo "Usage:"
	@echo "  make [ARCH=arm64|x86_64] [target]"
	@echo ""
	@echo "Architectures:"
	@echo "  arm64   - ARM64/AArch64 (default)"
	@echo "  x86_64  - Intel/AMD x86_64"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build all components (kvm, rkvm, qemu, guest)"
	@echo "  kvm     - Build C kernel module (ARM64 only)"
	@echo "  rkvm    - Build Rust kernel module"
	@echo "  qemu    - Build Rust VMM"
	@echo "  guest   - Build guest binary"
	@echo "  deploy  - Deploy to rootfs"
	@echo "  run     - Run QEMU"
	@echo "  clean   - Clean current architecture"
	@echo "  clean-all - Clean all architectures"
	@echo "  info    - Display build configuration"
	@echo "  help    - Display this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make ARCH=arm64 all    - Build for ARM64"
	@echo "  make ARCH=x86_64 all   - Build for x86_64"
	@echo "  make ARCH=x86_64 run   - Run x86_64 QEMU"