/*
 * guest.S - Minimal x86-64 bare-metal guest
 * 
 * This is a simple assembly program that:
 * 1. Writes characters to a simulated UART via MMIO
 * 2. Halts using HLT instruction
 * 
 * Build: as -64 -o guest.o guest.S
 *        objcopy -O binary guest.o guest.bin
 */

.section .text
.code64
.globl _start

_start:
    /* Set up register rax with UART MMIO address */
    movq $0x90000000, %rax
    
    /* Write 'H' */
    movb $0x48, (%rax)
    
    /* Write 'e' */
    movb $0x65, (%rax)
    
    /* Write 'l' */
    movb $0x6C, (%rax)
    
    /* Write 'l' */
    movb $0x6C, (%rax)
    
    /* Write 'o' */
    movb $0x6F, (%rax)
    
    /* Write ' ' (space) */
    movb $0x20, (%rax)
    
    /* Write 'K' */
    movb $0x4B, (%rax)
    
    /* Write 'V' */
    movb $0x56, (%rax)
    
    /* Write 'M' */
    movb $0x4D, (%rax)
    
    /* Write '!' */
    movb $0x21, (%rax)
    
    /* Write '\n' */
    movb $0x0A, (%rax)

halt:
    /* Halt the CPU using HLT instruction */
    hlt
    jmp halt