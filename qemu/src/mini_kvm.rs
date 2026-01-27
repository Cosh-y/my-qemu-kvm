/*
 * mini_kvm.rs - Rust bindings for mini_kvm kernel module
 * 
 * This module provides safe Rust wrappers around the ioctl interface
 * to communicate with the mini_kvm kernel module.
 */

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::io;

// Import architecture-specific register definitions
#[cfg(target_arch = "aarch64")]
use crate::arch::arm64::MiniKvmRegs;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86::MiniKvmRegs;

// ioctl helper macros
macro_rules! request_code_none {
    ($magic:expr, $nr:expr) => {
        (0u64 << 30) | (($magic as u64) << 8) | ($nr as u64)
    };
}

macro_rules! request_code_write {
    ($magic:expr, $nr:expr, $size:expr) => {
        (1u64 << 30) | (($size as u64) << 16) | (($magic as u64) << 8) | ($nr as u64)
    };
}

macro_rules! request_code_read {
    ($magic:expr, $nr:expr, $size:expr) => {
        (2u64 << 30) | (($size as u64) << 16) | (($magic as u64) << 8) | ($nr as u64)
    };
}

// ioctl definitions
const MINIKVM_MAGIC: u8 = 0xAE;

const MINIKVM_CREATE_VM: u64 = request_code_none!(MINIKVM_MAGIC, 1);
const MINIKVM_CREATE_VCPU: u64 = request_code_none!(MINIKVM_MAGIC, 2);
const MINIKVM_RUN: u64 = request_code_read!(MINIKVM_MAGIC, 3, std::mem::size_of::<MiniKvmRunState>());
const MINIKVM_SET_REGS: u64 = request_code_write!(MINIKVM_MAGIC, 4, std::mem::size_of::<MiniKvmRegs>());
const MINIKVM_GET_REGS: u64 = request_code_read!(MINIKVM_MAGIC, 5, std::mem::size_of::<MiniKvmRegs>());
const MINIKVM_SET_MEM: u64 = request_code_write!(MINIKVM_MAGIC, 6, std::mem::size_of::<MiniKvmMemRegion>());

// Rust representations of C structs from mini_kvm.h
// Note: MiniKvmRegs is imported from arch module above

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MiniKvmMemRegion {
    pub host_virt_addr: u64,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniKvmMmio {
    pub phys_addr: u64,
    pub data: u64,
    pub len: u32,
    pub is_write: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniKvmInternalError {
    pub error_code: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniKvmRunState {
    pub exit_reason: u32,
    pub padding: u32,
    pub mmio: MiniKvmMmio,
    pub internal_error: MiniKvmInternalError,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmExitReason {
    Unknown = 0,
    Mmio = 1,
    Hlt = 2,
    Shutdown = 3,
    InternalError = 4,
}

impl VmExitReason {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => VmExitReason::Mmio,
            2 => VmExitReason::Hlt,
            3 => VmExitReason::Shutdown,
            4 => VmExitReason::InternalError,
            _ => VmExitReason::Unknown,
        }
    }
}

pub struct MiniKvm {
    device: File,
    // hva
    guest_mem_ptr: Option<*mut libc::c_void>,
    guest_mem_size: usize,
    // gpa
    guest_phys_addr: u64,
}

impl MiniKvm {
    pub fn new() -> io::Result<Self> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/rkvm")?;
        
        Ok(MiniKvm {
            device,
            guest_mem_ptr: None,
            guest_mem_size: 0,
            guest_phys_addr: 0,
        })
    }
    
    pub fn create_vm(&mut self) -> io::Result<()> {
        unsafe {
            let ret = libc::ioctl(self.device.as_raw_fd(), MINIKVM_CREATE_VM);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    
    pub fn create_vcpu(&mut self) -> io::Result<()> {
        unsafe {
            let ret = libc::ioctl(self.device.as_raw_fd(), MINIKVM_CREATE_VCPU);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    
    pub fn set_regs(&mut self, regs: &MiniKvmRegs) -> io::Result<()> {
        unsafe {
            let ret = libc::ioctl(
                self.device.as_raw_fd(),
                MINIKVM_SET_REGS,
                regs as *const MiniKvmRegs,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    
    pub fn get_regs(&mut self) -> io::Result<MiniKvmRegs> {
        let mut regs = MiniKvmRegs::default();
        unsafe {
            let ret = libc::ioctl(
                self.device.as_raw_fd(),
                MINIKVM_GET_REGS,
                &mut regs as *mut MiniKvmRegs,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(regs)
    }
    
    pub fn allocate_memory(&mut self, guest_phys_addr: u64, size: usize) -> io::Result<()> {
        // Use mmap to allocate memory for the guest
        let mem_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        
        if mem_ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        
        // Store memory information
        self.guest_mem_ptr = Some(mem_ptr);
        self.guest_mem_size = size;
        self.guest_phys_addr = guest_phys_addr;
        
        // Create memory region structure
        let region = MiniKvmMemRegion {
            host_virt_addr: mem_ptr as u64,
            guest_phys_addr,
            memory_size: size as u64,
        };
        
        // Set memory region via ioctl
        unsafe {
            let ret = libc::ioctl(
                self.device.as_raw_fd(),
                MINIKVM_SET_MEM,
                &region as *const MiniKvmMemRegion,
            );
            if ret < 0 {
                // Clean up the mmap on failure
                libc::munmap(mem_ptr, size);
                self.guest_mem_ptr = None;
                self.guest_mem_size = 0;
                self.guest_phys_addr = 0;
                return Err(io::Error::last_os_error());
            }
        }
        
        Ok(())
    }
    
    pub fn write_guest_memory(&mut self, data: &[u8]) -> io::Result<()> {
        // Ensure memory has been allocated
        let mem_ptr = self.guest_mem_ptr.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Guest memory not allocated")
        })?;
        
        // Check if data fits in allocated memory
        if data.len() > self.guest_mem_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Data size ({} bytes) exceeds allocated memory ({} bytes)",
                    data.len(),
                    self.guest_mem_size
                ),
            ));
        }
        
        // Copy data to guest memory
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                mem_ptr as *mut u8,
                data.len(),
            );
        }
        
        Ok(())
    }
    
    pub fn run(&mut self) -> io::Result<MiniKvmRunState> {
        let mut run_state = MiniKvmRunState {
            exit_reason: 0,
            padding: 0,
            mmio: MiniKvmMmio {
                phys_addr: 0,
                data: 0,
                len: 0,
                is_write: 0,
                padding: [0; 3],
            },
            internal_error: MiniKvmInternalError { error_code: 0, padding: 0 },
        };
        
        unsafe {
            let ret = libc::ioctl(
                self.device.as_raw_fd(),
                MINIKVM_RUN,
                &mut run_state as *mut MiniKvmRunState,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        
        Ok(run_state)
    }
}

impl Drop for MiniKvm {
    fn drop(&mut self) {
        // Unmap guest memory if allocated
        if let Some(mem_ptr) = self.guest_mem_ptr {
            unsafe {
                libc::munmap(mem_ptr, self.guest_mem_size);
            }
        }
        // File will be automatically closed
    }
}
