# Makefile for RKVM-x86 - Rust KVM kernel module for x86_64
# 
# This Makefile builds the Rust-based KVM module for x86_64/Intel VT-x

LINUX_DIR ?= /home/m/chy/linux-6.18.5

# Kernel build directory
KDIR := $(LINUX_DIR)

CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)gcc

# Kernel module name
MODULE_NAME := rkvm_x86

.PHONY: all clean build

# ============================================
# Main Targets
# ============================================

build: all

all: 
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=1 ARCH=x86_64 modules

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=x86_64 clean
	rm -rf target/

# Install module
install: all
	sudo insmod $(MODULE_NAME).ko

# Uninstall module
uninstall:
	sudo rmmod $(MODULE_NAME)

# View kernel logs
log:
	dmesg | tail -50 | grep -i "rkvm\|vmx\|kvm"