/*
 * guest.S - Minimal ARM64 bare-metal guest
 * 
 * This is a simple assembly program that:
 * 1. Writes characters to a simulated UART via MMIO
 * 2. Halts using WFI instruction
 * 
 * Build: aarch64-linux-gnu-as -o guest.o guest.S
 *        aarch64-linux-gnu-objcopy -O binary guest.o guest.bin
 */

.section .text
.global _start

_start:
    /* Set up register x0 with UART MMIO address */
    mov x0, #0x09000000
    
    /* Write 'H' */
    mov x1, #0x48
    str x1, [x0]
    
    /* Write 'e' */
    mov x1, #0x65
    str x1, [x0]
    
    /* Write 'l' */
    mov x1, #0x6C
    str x1, [x0]
    
    /* Write 'l' */
    mov x1, #0x6C
    str x1, [x0]
    
    /* Write 'o' */
    mov x1, #0x6F
    str x1, [x0]
    
    /* Write ' ' (space) */
    mov x1, #0x20
    str x1, [x0]
    
    /* Write 'K' */
    mov x1, #0x4B
    str x1, [x0]
    
    /* Write 'V' */
    mov x1, #0x56
    str x1, [x0]
    
    /* Write 'M' */
    mov x1, #0x4D
    str x1, [x0]
    
    /* Write '!' */
    mov x1, #0x21
    str x1, [x0]
    
    /* Write '\n' */
    mov x1, #0x0A
    str x1, [x0]

halt:
    /* Halt the CPU using WFI (Wait For Interrupt) */
    wfi
    b halt
