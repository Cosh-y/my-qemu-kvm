//! simple x86 instruction parser, helper for VM Exit handling
#![allow(missing_docs)]
use kernel::prelude::*;

use crate::types::*;
use crate::vm::X86Vm;
use crate::wrap::{copy_from_user, copy_to_user};

impl X86Vm {
    pub fn read_instruction(&self, rip: GuestPhysAddr, buf: &mut [u8]) -> Result<()> {
        for mem in self.get_memory() {
            let base = mem.guest_phys_addr_base();
            let size = (mem.get_pages_count() as u64) << 12;
            
            // Check if RIP falls within this memory region
            if rip >= base && rip < base + size {
                // Check if instruction extends beyond this region
                if (rip - base) + (buf.len() as u64) > size {
                    return Err(EFAULT);
                }
                
                let offset = (rip - base) as usize;
                let hva = mem.virt_addr_base() + offset;
                
                copy_from_user(
                    buf.as_mut_ptr() as *mut c_void, 
                    hva as *const c_void, 
                    buf.len()
                )?;
                return Ok(());
            }
        }
        
        // No matching memory region found
        Err(EFAULT)
    }
}

pub fn mov_parser(instruction: &[u8]) -> Option<(u64, u64)> {
    // return (len, value)
    // 1. 安全检查：确保切片长度至少为 3 字节 (Opcode + ModR/M + Imm8)
    if instruction.len() < 3 {
        return None;
    }

    // 2. 解析 Opcode (0xC6)
    // 0xC6 是 "Move immediate byte to r/m8" 的操作码
    if instruction[0] != 0xC6 {
        return None; 
    }

    // 3. 解析 ModR/M 字节
    // 我们期望的是: movb $imm, (%rax)
    // 二进制结构: [Mod: 00] [Reg/Op: 000] [R/M: 000]
    // Mod 00 = Register Indirect Addressing (即 [rax])
    // Reg 000 = Opcode Extension (0xC6 需要 reg 字段为 0)
    // R/M 000 = RAX
    // 组合结果 = 0b00_000_000 = 0x00
    if instruction[1] != 0x00 {
        // 如果你需要支持其他寄存器，比如 (%rbx) -> 0x03, (%rcx) -> 0x01，可以在这里扩展
        return None;
    }

    // 4. 获取立即数 (Immediate Value)
    // 第三个字节就是要写入内存的值
    let imm_value = instruction[2];

    // 5. 返回结果
    // 指令长度固定为 3
    // 将 u8 转换为 u64 返回
    Some((3, imm_value as u64))
}
