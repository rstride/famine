section .data
    directory db "/tmp/test/", 0
    signature db "Famine version 1.0 (c)oded by rstride", 0
    signature_length equ $ - signature

    debug_msg db "Processing file...\n", 0
    debug_msg_len equ $ - debug_msg

section .bss
    dirfd resb 4                ; File descriptor for the directory
    filefd resb 4               ; File descriptor for the file
    elf_header resb 64          ; ELF header buffer (use 64 bytes for a full header check)
    buffer resb 1024            ; Buffer for directory reading
    statbuf resb 144            ; Buffer for fstat (size is 144 bytes on 64-bit systems)
    number_buffer resb 20       ; Buffer for converting numbers to strings

section .text
    global _start

_start:
    ; Open the directory
    mov rax, 2                  ; Syscall for 'open'
    mov rdi, directory           ; Directory path
    xor rsi, rsi                ; Flags: read-only
    syscall                     ; Make the syscall
    mov [dirfd], eax            ; Store the directory file descriptor (32-bit)

    ; Check if the directory was opened successfully
    test eax, eax
    js _exit                    ; If less than 0, exit (error)

read_directory:
    ; Read directory contents
    mov rax, 78                 ; Syscall for 'getdents64'
    mov edi, [dirfd]            ; Directory file descriptor
    mov rsi, buffer             ; Buffer to store directory entries
    mov edx, 1024               ; Size of the buffer
    syscall                     ; Make the syscall

    ; Check if the read was successful
    test rax, rax
    jle _exit                   ; If less than or equal to 0, exit (error or end of directory)

    ; Store the number of bytes read in rcx
    mov rcx, rax                ; rcx now stores the number of bytes read (112 in your case)

    ; Print RCX value (for debugging)
    call write_rcx_value

    ; Process directory entries
    mov rbx, buffer             ; rbx points to the start of the buffer
    jmp process_entry           ; Jump to process the directory entries

process_entry:
    ; Check if we've reached the end of the buffer
    cmp rcx, 0
    je _exit                    ; If rcx == 0, exit

    ; Get the length of the entry (d_reclen, 2 bytes at offset 18)
    movzx rdx, word [rbx + 16]  ; Load the length of the entry (d_reclen)
    
    ; Process entry
    ; (handling regular files, fstat, etc.)

next_entry:
    ; Move to the next entry
    add rbx, rdx                ; Move rbx by the length of the entry (d_reclen)
    sub rcx, rdx                ; Decrease the byte count
    jmp process_entry

convert_to_string:
    ; Converts RCX (in rdi) to a string and stores it in number_buffer
    ; Output: number_buffer (in RSI)

    mov rsi, number_buffer      ; Buffer to store the string
    mov rcx, 10                 ; Base 10
    mov rbx, rdi                ; Copy RDI (value) to RBX for division
    mov rdi, rsi                ; Pointer to string buffer

    mov rdx, 0                  ; Clear RDX

convert_loop:
    xor rdx, rdx                ; Clear remainder
    div rcx                     ; Divide rbx by 10 (quotient in rax, remainder in rdx)
    add dl, '0'                 ; Convert remainder to ASCII
    dec rdi                     ; Move pointer to store digits from the end
    mov [rdi], dl               ; Store digit
    test rax, rax               ; Check if quotient is 0
    jnz convert_loop            ; Continue if there is more to divide

    ret

write_rcx_value:
    ; Convert RCX to a string and write it to stderr
    mov rdi, rcx                ; Value of RCX
    call convert_to_string      ; Convert RCX to string in number_buffer

    ; Write the converted number to stderr
    mov rax, 1                  ; Syscall number for 'write'
    mov rdi, 2                  ; File descriptor (2 for stderr)
    mov rsi, number_buffer      ; Buffer containing the string
    mov rdx, 20                 ; Maximum length of the buffer
    syscall
    ret

debug_print:
    ; Print debug message
    mov rax, 1                  ; Syscall for 'write'
    mov rdi, 2                  ; File descriptor 2 (stderr)
    mov rsi, debug_msg          ; Debug message
    mov rdx, debug_msg_len      ; Length of the message
    syscall
    ret

_exit:
    mov rax, 60                 ; Syscall for 'exit'
    xor edi, edi                ; Exit code 0
    syscall
