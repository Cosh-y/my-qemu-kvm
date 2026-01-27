/*
 * main.rs - Minimal QEMU-like VMM in Rust
 * 
 * This userspace program manages the VM through the mini_kvm kernel module.
 * Responsibilities:
 * - Allocate and manage guest memory
 * - Load guest binary into memory
 * - Handle MMIO exits (emulate devices like UART)
 * - Control VM execution loop
 */

mod mini_kvm;
mod arch;

use mini_kvm::{MiniKvm, VmExitReason};
#[cfg(target_arch = "aarch64")]
use arch::arm64::MiniKvmRegs;
#[cfg(target_arch = "x86_64")]
use arch::x86::MiniKvmRegs;
use std::env;
use std::fs::File;
use std::io::Read;

const GUEST_MEM_SIZE: usize = 4096; // 4KB for minimal test
const GUEST_ENTRY: u64 = 0x40000000; // Guest physical address

struct UartDevice {
    output_buffer: Vec<u8>,
}

impl UartDevice {
    fn new() -> Self {
        UartDevice {
            output_buffer: Vec::new(),
        }
    }
    
    fn write(&mut self, data: u64) {
        let byte = (data & 0xFF) as u8;
        
        // Print character if printable
        if byte >= 0x20 && byte <= 0x7E {
            print!("{}", byte as char);
        } else if byte == b'\n' {
            println!();
        } else if byte == b'\r' {
            // Ignore carriage return
        } else {
            print!("<0x{:02x}>", byte);
        }
        
        self.output_buffer.push(byte);
        
        // Flush stdout
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }
    
    fn read(&self) -> u64 {
        // Simple implementation: always return 0
        0
    }
}

fn main() {
    println!("===========================================");
    println!("  Mini QEMU - Userspace VMM");
    println!("===========================================\n");

    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <guest-binary>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} guest.bin", args[0]);
        std::process::exit(1);
    }

    let guest_binary = &args[1];

    println!("[VMM] Opening mini_kvm device...");
    
    // Open the kernel module device
    let mut kvm = match MiniKvm::new() {
        Ok(kvm) => {
            println!("[VMM] Successfully opened /dev/mini_kvm");
            kvm
        }
        Err(e) => {
            eprintln!("[VMM] Failed to open /dev/mini_kvm: {}", e);
            eprintln!("\nMake sure the kernel module is loaded:");
            eprintln!("  sudo insmod kvm/mini_kvm.ko");
            std::process::exit(1);
        }
    };

    println!("[VMM] Creating VM...");
    if let Err(e) = kvm.create_vm() {
        eprintln!("[VMM] Failed to create VM: {}", e);
        std::process::exit(1);
    }
    println!("[VMM] VM created successfully");

    println!("[VMM] Creating vCPU...");
    if let Err(e) = kvm.create_vcpu() {
        eprintln!("[VMM] Failed to create vCPU: {}", e);
        std::process::exit(1);
    }
    println!("[VMM] vCPU created successfully");

    println!("[VMM] Allocating guest memory ({} bytes)...", GUEST_MEM_SIZE);
    if let Err(e) = kvm.allocate_memory(GUEST_ENTRY, GUEST_MEM_SIZE) {
        eprintln!("[VMM] Failed to allocate memory: {}", e);
        std::process::exit(1);
    }
    
    println!("[VMM] Loading guest binary: {}", guest_binary);
    let guest_code = match load_guest_binary(guest_binary) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[VMM] Failed to load guest binary: {}", e);
            std::process::exit(1);
        }
    };
    
    if guest_code.len() > GUEST_MEM_SIZE {
        eprintln!("[VMM] Guest binary too large: {} > {}", guest_code.len(), GUEST_MEM_SIZE);
        std::process::exit(1);
    }
    
    // Write guest code to memory
    if let Err(e) = kvm.write_guest_memory(&guest_code) {
        eprintln!("[VMM] Failed to write guest memory: {}", e);
        std::process::exit(1);
    }
    println!("[VMM] Guest code (len={}) written to memory", guest_code.len());

    // Set initial guest registers
    println!("[VMM] Setting initial vCPU state...");
    
    #[cfg(target_arch = "aarch64")]
    let regs = {
        let mut regs = MiniKvmRegs::default();
        regs.pc = GUEST_ENTRY;
        regs.sp = GUEST_ENTRY + (GUEST_MEM_SIZE as u64) - 16;
        regs.pstate = 0x3c5; // EL1h, IRQ/FIQ masked
        println!("[VMM] Initial state: PC=0x{:x}, SP=0x{:x}", regs.pc, regs.sp);
        regs
    };
    
    #[cfg(target_arch = "x86_64")]
    let regs = {
        let mut regs = MiniKvmRegs::default();
        regs.rip = GUEST_ENTRY;
        regs.rsp = GUEST_ENTRY + (GUEST_MEM_SIZE as u64) - 16;
        regs.rflags = 0x2; // Reserved bit must be set
        println!("[VMM] Initial state: RIP=0x{:x}, RSP=0x{:x}", regs.rip, regs.rsp);
        regs
    };
    
    if let Err(e) = kvm.set_regs(&regs) {
        eprintln!("[VMM] Failed to set registers: {}", e);
        std::process::exit(1);
    }

    // Create UART device
    let mut uart = UartDevice::new();
    
    println!("\n===========================================");
    println!("  Starting VM Execution");
    println!("===========================================\n");
    println!("[GUEST OUTPUT]:");

    // Main VM execution loop
    let mut iteration = 0;
    let max_iterations = 1000;
    
    loop {
        iteration += 1;
        
        // Run the vCPU
        match kvm.run() {
            Ok(run_state) => {
                match VmExitReason::from_u32(run_state.exit_reason) {
                    VmExitReason::Mmio => {
                        // Handle MMIO access - no need for unsafe, fields are always present
                        if run_state.mmio.is_write != 0 {
                            // MMIO write - emulate UART output
                            uart.write(run_state.mmio.data);
                        } else {
                            // MMIO read - return data (not implemented in this simple version)
                            println!("\n[VMM] MMIO Read: addr=0x{:x}, len={}", 
                                    run_state.mmio.phys_addr, run_state.mmio.len);
                        }
                    }
                    VmExitReason::Hlt => {
                        println!("\n[VMM] Guest halted (WFI instruction)");
                        break;
                    }
                    VmExitReason::Shutdown => {
                        println!("\n[VMM] Guest requested shutdown");
                        break;
                    }
                    VmExitReason::InternalError => {
                        eprintln!("\n[VMM] Internal error: code={}", run_state.internal_error.error_code);
                        break;
                    }
                    VmExitReason::Unknown => {
                        // Continue execution for unknown reasons
                        if iteration % 100 == 0 {
                            println!("\n[VMM] Unknown exit at iteration {}", iteration);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("\n[VMM] Failed to run vCPU: {}", e);
                break;
            }
        }

        // Safety limit
        if iteration >= max_iterations {
            println!("\n[VMM] Reached maximum iterations ({}), stopping", max_iterations);
            break;
        }
    }

    println!("\n===========================================");
    println!("  VM Execution Complete");
    println!("===========================================");
    println!("Total iterations: {}", iteration);
    println!("UART output buffer: {} bytes", uart.output_buffer.len());
    println!("\nVMM shutting down...");
}

fn load_guest_binary(filename: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}
