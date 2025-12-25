# Makefile for Mini KVM/QEMU Project
# Support for cross-compilation and QEMU testing environment

# ============================================
# Configuration
# ============================================

# Buildroot paths (adjust if needed)
BUILDROOT_DIR ?= /home/m/buildroot
BUILDROOT_HOST := $(BUILDROOT_DIR)/output/host
BUILDROOT_TARGET := $(BUILDROOT_DIR)/output/target
BUILDROOT_IMAGES := $(BUILDROOT_DIR)/output/images

# Kernel build directory (for target ARM64 kernel)
KDIR := $(BUILDROOT_DIR)/output/build/linux-*

# Cross-compilation toolchain
CROSS_COMPILE := $(BUILDROOT_HOST)/bin/aarch64-buildroot-linux-gnu-
CC := $(CROSS_COMPILE)gcc
AS := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy

# QEMU settings
QEMU := qemu-system-aarch64
KERNEL := $(BUILDROOT_IMAGES)/Image
ROOTFS := $(BUILDROOT_IMAGES)/rootfs.ext4
QEMU_FLAGS := -M virt,gic-version=3,virtualization=on \
              -cpu cortex-a57 \
              -nographic \
              -smp 2 \
              -m 2048 \
              -kernel $(KERNEL) \
              -append "root=/dev/vda rw console=ttyAMA0" \
              -drive if=none,file=$(ROOTFS),format=raw,id=hd0 \
              -device virtio-blk-device,drive=hd0

# Deployment paths
MOUNT_POINT := /tmp/mykvm_rootfs
DEPLOY_ROOT := $(MOUNT_POINT)/root/mykvm
DEPLOY_KVM := $(DEPLOY_ROOT)/kvm
DEPLOY_QEMU := $(DEPLOY_ROOT)/qemu
DEPLOY_GUEST := $(DEPLOY_ROOT)/guest

# Rust settings
CARGO := cargo
CARGO_TARGET := aarch64-unknown-linux-gnu

.PHONY: all clean kernel vmm guest deploy test_qemu help check_buildroot mount_rootfs umount_rootfs

# ============================================
# Main Targets
# ============================================

all: kernel vmm guest

help:
	@echo "Mini KVM/QEMU Cross-Compilation Build System"
	@echo "=============================================="
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Buildroot at: $(BUILDROOT_DIR)"
	@echo "  - Linux kernel built in Buildroot"
	@echo "  - Rootfs image available"
	@echo ""
	@echo "Available targets:"
	@echo "  all            - Build everything (kernel module + VMM + guest)"
	@echo "  kernel         - Build kernel module (cross-compiled)"
	@echo "  vmm            - Build Rust VMM (cross-compiled)"
	@echo "  guest          - Build guest binary (cross-compiled)"
	@echo "  deploy          - Deploy files to rootfs.ext4 (auto mount/umount)"
	@echo "  test_qemu       - Run QEMU with test environment"
	@echo "  check_buildroot - Verify Buildroot paths"
	@echo "  mount_rootfs    - Manually mount rootfs.ext4"
	@echo "  umount_rootfs   - Manually unmount rootfs.ext4"
	@echo "  clean           - Clean all build artifacts"
	@echo ""
	@echo "Typical workflow:"
	@echo "  1. make all          # Build all components"
	@echo "  2. sudo make deploy  # Deploy to rootfs.ext4 (requires sudo)"
	@echo "  3. make test_qemu    # Boot QEMU and test"
	@echo ""
	@echo "Inside QEMU guest:"
	@echo "  # cd /root/mykvm"
	@echo "  # insmod kvm/mini_kvm.ko"
	@echo "  # ./qemu/mini-qemu guest/guest.bin"
	@echo ""

# ============================================
# Build Targets
# ============================================

# Check Buildroot paths
check_buildroot:
	@echo "Checking Buildroot configuration..."
	@if [ ! -d "$(BUILDROOT_DIR)" ]; then \
		echo "ERROR: Buildroot directory not found: $(BUILDROOT_DIR)"; \
		echo "Please set BUILDROOT_DIR to your Buildroot path"; \
		exit 1; \
	fi
	@if [ ! -d "$(BUILDROOT_HOST)" ]; then \
		echo "ERROR: Buildroot host directory not found: $(BUILDROOT_HOST)"; \
		echo "Please build Buildroot first"; \
		exit 1; \
	fi
	@if [ ! -f "$(KERNEL)" ]; then \
		echo "ERROR: Kernel image not found: $(KERNEL)"; \
		echo "Please build the kernel in Buildroot"; \
		exit 1; \
	fi
	@if [ ! -f "$(ROOTFS)" ]; then \
		echo "ERROR: Rootfs image not found: $(ROOTFS)"; \
		echo "Please build the rootfs in Buildroot"; \
		exit 1; \
	fi
	@echo "✓ Buildroot found at: $(BUILDROOT_DIR)"
	@echo "✓ Host tools at: $(BUILDROOT_HOST)"
	@echo "✓ Kernel image: $(KERNEL)"
	@echo "✓ Rootfs image: $(ROOTFS)"
	@echo ""

# Build kernel module (cross-compiled)
kernel: check_buildroot
	@echo "Building kernel module for ARM64..."
	@if [ -z "$(wildcard $(KDIR))" ]; then \
		echo "ERROR: Kernel build directory not found"; \
		echo "Expected pattern: $(KDIR)"; \
		exit 1; \
	fi
	$(MAKE) -C $(wildcard $(KDIR)) M=$(PWD)/kvm ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules
	@echo "✓ Kernel module built: kvm/mini_kvm.ko"
	@file kvm/mini_kvm.ko

# Build Rust VMM (cross-compiled)
vmm: check_buildroot
	@echo "Building Rust VMM for ARM64..."
	@echo "Using Buildroot toolchain from: $(BUILDROOT_HOST)"
	cd qemu && $(CARGO) build --release
	@echo "✓ VMM built: qemu/target/$(CARGO_TARGET)/release/mini-qemu"
	@file qemu/target/$(CARGO_TARGET)/release/mini-qemu

# Build guest binary (cross-compiled)
guest: guest/guest.bin

guest/guest.o: guest/guest.S check_buildroot
	@echo "Assembling guest code for ARM64..."
	$(AS) -o guest/guest.o guest/guest.S

guest/guest.bin: guest/guest.o
	@echo "Creating guest binary..."
	$(OBJCOPY) -O binary guest/guest.o guest/guest.bin
	@echo "✓ Guest binary created: guest/guest.bin"
	@echo "  Size: $$(stat -c%s guest/guest.bin) bytes"
	@file guest/guest.bin

# ============================================
# Deployment (Direct rootfs.ext4 mounting)
# ============================================

# Mount rootfs.ext4
mount_rootfs: check_buildroot
	@echo "Mounting rootfs.ext4..."
	@if mountpoint -q $(MOUNT_POINT); then \
		echo "✓ Already mounted at $(MOUNT_POINT)"; \
	else \
		mkdir -p $(MOUNT_POINT); \
		sudo mount -o loop $(ROOTFS) $(MOUNT_POINT); \
		echo "✓ Mounted $(ROOTFS) at $(MOUNT_POINT)"; \
	fi

# Unmount rootfs.ext4
umount_rootfs:
	@echo "Unmounting rootfs.ext4..."
	@if mountpoint -q $(MOUNT_POINT); then \
		sudo umount $(MOUNT_POINT); \
		echo "✓ Unmounted $(MOUNT_POINT)"; \
	else \
		echo "Not mounted"; \
	fi

# Deploy files to rootfs.ext4
deploy: all mount_rootfs
	@echo ""
	@echo "=========================================="
	@echo "  Deploying to Rootfs Image"
	@echo "=========================================="
	@echo ""
	@echo "Target: $(ROOTFS)"
	@echo "Mount point: $(MOUNT_POINT)"
	@echo ""
	@echo "Creating directory structure..."
	sudo mkdir -p $(DEPLOY_KVM)
	sudo mkdir -p $(DEPLOY_QEMU)
	sudo mkdir -p $(DEPLOY_GUEST)
	@echo ""
	@echo "Copying kernel module..."
	sudo cp kvm/mini_kvm.ko $(DEPLOY_KVM)/
	@echo ""
	@echo "Copying VMM binary..."
	sudo cp qemu/target/$(CARGO_TARGET)/release/mini-qemu $(DEPLOY_QEMU)/
	@echo ""
	@echo "Copying guest binary..."
	sudo cp guest/guest.bin $(DEPLOY_GUEST)/
	@echo ""
	@echo "Creating test script..."
	@echo '#!/bin/sh' | sudo tee $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "=========================================="' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "  Mini KVM/QEMU Test Script"' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "=========================================="' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'cd /root/mykvm' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "Step 1: Loading kernel module..."' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'insmod kvm/mini_kvm.ko' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'if [ $$? -ne 0 ]; then' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo '    echo "ERROR: Failed to load kernel module"' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo '    exit 1' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'fi' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "Step 2: Checking device..."' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'ls -l /dev/mini_kvm' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "Step 3: Running mini-qemu..."' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo './qemu/mini-qemu guest/guest.bin' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "Step 4: Checking kernel log..."' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'dmesg | grep mini_kvm | tail -20' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "Step 5: Unloading module..."' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'rmmod mini_kvm' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo ""' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	@echo 'echo "Test complete!"' | sudo tee -a $(DEPLOY_ROOT)/test.sh > /dev/null
	sudo chmod +x $(DEPLOY_ROOT)/test.sh
	@echo ""
	@echo "Syncing filesystem..."
	sync
	@echo ""
	@$(MAKE) umount_rootfs
	@echo ""
	@echo "✓ Deployment complete!"
	@echo ""
	@echo "Files deployed to rootfs.ext4:"
	@echo "  - /root/mykvm/kvm/mini_kvm.ko"
	@echo "  - /root/mykvm/qemu/mini-qemu"
	@echo "  - /root/mykvm/guest/guest.bin"
	@echo "  - /root/mykvm/test.sh"
	@echo ""
	@echo "✓ Changes are permanent in $(ROOTFS)"
	@echo "  No need to run 'buildroot make'!"
	@echo ""

# ============================================
# QEMU Testing
# ============================================

test_qemu: check_buildroot
	@echo ""
	@echo "=========================================="
	@echo "  Starting QEMU Test Environment"
	@echo "=========================================="
	@echo ""
	@echo "QEMU Configuration:"
	@echo "  Machine: virt (ARM64)"
	@echo "  CPU: cortex-a57 (with virtualization)"
	@echo "  RAM: 2048 MB"
	@echo "  Cores: 2"
	@echo "  Kernel: $(KERNEL)"
	@echo "  Rootfs: $(ROOTFS)"
	@echo ""
	@echo "After boot, run:"
	@echo "  # cd /root/mykvm"
	@echo "  # ./test.sh"
	@echo ""
	@echo "Or manually:"
	@echo "  # insmod kvm/mini_kvm.ko"
	@echo "  # ./qemu/mini-qemu guest/guest.bin"
	@echo "  # rmmod mini_kvm"
	@echo ""
	@echo "To exit QEMU: Ctrl-A, then X"
	@echo ""
	@read -p "Press Enter to start QEMU..." dummy
	$(QEMU) $(QEMU_FLAGS)

# ============================================
# Cleaning
# ============================================

clean:
	@echo "Cleaning build artifacts..."
	@if [ -n "$(wildcard $(KDIR))" ]; then \
		$(MAKE) -C $(wildcard $(KDIR)) M=$(PWD)/kvm ARCH=arm64 clean 2>/dev/null || true; \
	fi
	cd qemu && $(CARGO) clean
	rm -f guest/guest.o guest/guest.bin
	rm -f kvm/*.o kvm/*.ko kvm/*.mod kvm/*.mod.c kvm/.*.cmd kvm/Module.symvers kvm/modules.order
	rm -rf kvm/.tmp_versions
	@echo "✓ Clean complete."

# Additional utility targets
.PHONY: info rebuild deploy-only

info:
	@echo "Build Configuration:"
	@echo "  Buildroot: $(BUILDROOT_DIR)"
	@echo "  Toolchain: $(CROSS_COMPILE)"
	@echo "  Target arch: ARM64"
	@echo "  Rust target: $(CARGO_TARGET)"
	@echo ""
	@echo "Paths:"
	@echo "  Kernel: $(KERNEL)"
	@echo "  Rootfs: $(ROOTFS)"
	@echo "  Deploy: $(DEPLOY_ROOT)"

rebuild: clean all

deploy-only:
	@echo "Deploying without rebuilding..."
	$(MAKE) deploy
