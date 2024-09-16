%include "constants.inc"
%include "data.inc"

section .text
    global _start
    global _exit
    extern _inject

_start:
    call _inject
    jmp _exit

_exit:
    mov rax, SYSCALL_EXIT   ; move exit syscall number into rax
    xor rdi, rdi            ; exit code 0
    syscall                 ; invoke system call to exit
