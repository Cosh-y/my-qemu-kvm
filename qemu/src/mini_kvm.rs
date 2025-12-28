/*
 * mini_kvm.rs - Rust bindings for mini_kvm kernel module
 * 
 * This module provides safe Rust wrappers around the ioctl interface
 * to communicate with the mini_kvm kernel module.
 */

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::io;

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

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct MiniKvmRegs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct MiniKvmMemRegion {
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
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
    guest_mem: Option<Vec<u8>>,
    guest_phys_addr: u64,
}

impl MiniKvm {
    pub fn new() -> io::Result<Self> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mini_kvm")?;
        
        Ok(MiniKvm {
            device,
            guest_mem: None,
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
        self.guest_phys_addr = guest_phys_addr;
        // Allocate userspace memory
        let mut mem = vec![0u8; size];
        
        let region = MiniKvmMemRegion {
            guest_phys_addr,
            memory_size: size as u64,
            userspace_addr: mem.as_ptr() as u64,
        };
        
        unsafe {
            let ret = libc::ioctl(
                self.device.as_raw_fd(),
                MINIKVM_SET_MEM,
                &region as *const MiniKvmMemRegion,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        
        // Keep the memory alive
        self.guest_mem = Some(mem);
        Ok(())
    }
    
    pub fn write_guest_memory(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(ref mut mem) = self.guest_mem {
            if data.len() > mem.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Data too large for guest memory",
                ));
            }
            mem[..data.len()].copy_from_slice(data);
            
            // Sync with kernel to ensure guest sees the code
            let region = MiniKvmMemRegion {
                guest_phys_addr: self.guest_phys_addr,
                memory_size: mem.len() as u64,
                userspace_addr: mem.as_ptr() as u64,
            };
            
            unsafe {
                let ret = libc::ioctl(
                    self.device.as_raw_fd(),
                    MINIKVM_SET_MEM,
                    &region as *const MiniKvmMemRegion,
                );
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Guest memory not allocated",
            ))
        }
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
        // File will be automatically closed
    }
}
