# Mini KVM/QEMU Makefile - Simplified

# Configuration
LINUX_DIR ?= /home/m/chy/linux-6.18.5
KDIR := $(LINUX_DIR)

CROSS_COMPILE ?= aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc
AS := $(CROSS_COMPILE)as
OBJCOPY := $(CROSS_COMPILE)objcopy

KERNEL ?= $(LINUX_DIR)/arch/arm64/boot/Image
ROOTFS ?= /home/m/chy/busybox-1.36.1/disk.img

QEMU := qemu-system-aarch64
QEMU_FLAGS := -machine virt,gic-version=3,virtualization=on \
              -cpu cortex-a57 \
              -m 512M \
              -nographic \
              -kernel $(KERNEL) \
              -append "root=/dev/vda1 console=ttyAMA0 rw kvm-arm.mode=none" \
              -drive file=$(ROOTFS),format=raw,id=hd0,if=virtio

MOUNT_POINT := /tmp/mykvm_rootfs
DEPLOY_ROOT := $(MOUNT_POINT)/root/mykvm

CARGO := cargo
CARGO_TARGET := aarch64-unknown-linux-gnu

.PHONY: all clean kvm rkvm qemu guest deploy mount umount run

all: kvm rkvm qemu guest

# Build C kernel module
kvm:
	$(MAKE) -C $(KDIR) M=$(PWD)/kvm LLVM=1 ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules

# Build Rust kernel module
rkvm:
	$(MAKE) -C rkvm LINUX_DIR=$(LINUX_DIR) CROSS_COMPILE=$(CROSS_COMPILE) build

# Build Rust VMM
qemu:
	cd qemu && $(CARGO) build --release --target $(CARGO_TARGET)

# Build guest binary
guest: guest/guest.bin

guest/guest.o: guest/guest.S
	$(AS) -o guest/guest.o guest/guest.S

guest/guest.bin: guest/guest.o
	$(OBJCOPY) -O binary guest/guest.o guest/guest.bin

# Mount rootfs
mount:
	@mkdir -p $(MOUNT_POINT)
	@mountpoint -q $(MOUNT_POINT) || sudo mount -o loop,offset=1048576 $(ROOTFS) $(MOUNT_POINT)

# Unmount rootfs
umount:
	@mountpoint -q $(MOUNT_POINT) && sudo umount $(MOUNT_POINT) || true

# Deploy files to rootfs
deploy: all mount
	@sudo mkdir -p $(DEPLOY_ROOT)/kvm $(DEPLOY_ROOT)/rkvm $(DEPLOY_ROOT)/qemu $(DEPLOY_ROOT)/guest
	@sudo cp kvm/mini_kvm.ko $(DEPLOY_ROOT)/kvm/
	@sudo cp rkvm/rkvm.ko $(DEPLOY_ROOT)/rkvm/
	@sudo cp qemu/target/$(CARGO_TARGET)/release/mini-qemu $(DEPLOY_ROOT)/qemu/
	@sudo cp guest/guest.bin $(DEPLOY_ROOT)/guest/
	@sync
	@$(MAKE) umount

# Run QEMU
run:
	$(QEMU) $(QEMU_FLAGS)

# Clean
clean:
	@$(MAKE) -C $(KDIR) M=$(PWD)/kvm ARCH=arm64 clean 2>/dev/null || true
	@$(MAKE) -C rkvm clean 2>/dev/null || true
	@cd qemu && $(CARGO) clean
	@rm -f guest/guest.o guest/guest.bin
	@rm -f kvm/*.o kvm/*.ko kvm/*.mod kvm/*.mod.c kvm/.*.cmd kvm/Module.symvers kvm/modules.order
	@rm -rf kvm/.tmp_versions
	@rm -f rkvm/*.o rkvm/*.ko rkvm/*.mod rkvm/*.mod.c rkvm/.*.cmd rkvm/Module.symvers rkvm/modules.order