%include "constants.inc"
%include "data.inc"

section .text
    global _start

_start:
    call _inject

_exit:
    push SYSCALL_EXIT
    rax ; exit
    xor rdi, rdi; = 0
    syscall