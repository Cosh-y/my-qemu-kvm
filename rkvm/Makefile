# Makefile for RKVM - Rust KVM kernel module
# 
# This Makefile builds the Rust-based KVM module for ARM64

LINUX_DIR ?= /home/m/chy/linux-6.18.5

# Kernel build directory
KDIR := $(LINUX_DIR)

CROSS_COMPILE ?= aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc

# Kernel module name
MODULE_NAME := rkvm

.PHONY: all clean build

# ============================================
# Main Targets
# ============================================

build: all

all: 
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=1 ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) modules

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) ARCH=arm64 CROSS_COMPILE=$(CROSS_COMPILE) clean
