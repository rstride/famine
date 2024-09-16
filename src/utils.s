%include "constants.inc"
%include "data.inc"

section .text
	global _ft_concat_path
	global _ft_isnum
	global _ft_strlen
	global _ft_memcmp
	global _ft_memmem
	global _ft_strcmp
	global _ft_strcpy
	global _ft_memcpy



_ft_concat_path: ;(string rdi, string rsi) -> rdi is dest, must be in stack or mmaped region
	push rdx

	mov rdx, rdi
	call _ft_strlen
	add rdi, rax
	mov byte[rdi], '/'
	inc rdi
	call _ft_strcpy
	push rdx
	pop rdi
	mov rax, rdi

	pop rdx
ret

_ft_isnum:; (string rdi) ; 0 no - otherwise rax something else
	xor rax, rax
	.loop_char:
		cmp byte[rdi + rax], 0x0
		je .return
		cmp byte[rdi + rax], '0'
		jl .isnotnum
		cmp byte[rdi + rax], '9'
		jg .isnotnum
		inc rax
	jmp .loop_char
	.isnotnum:
		xor rax, rax
	.return:
ret

_ft_strlen:; (string rdi)
	xor rax, rax; = 0
	.loop_char:
		cmp byte [rdi + rax], 0
		jz .return
		inc rax
	jmp .loop_char
	.return:
ret

_ft_memcmp: ; (void *rdi, void *rsi, size_t rdx)
	push rcx
	dec rdx

	xor rax, rax
	xor rcx, rcx; = 0
	.loop_byte:
		mov al, [rdi + rcx]
		cmp al, [rsi + rcx]
		jne .return
		cmp rcx, rdx
		je .return
		inc rcx
	jmp .loop_byte
	.return:
		sub al, [rsi + rcx]

	inc rdx
	pop rcx
ret

_ft_memmem: ; (void *rdi, size_t rsi, void *rdx, size_t rcx)
	push r8
	push r9
	push rbx

	xor rax,rax
	xor r8, r8
	sub rsi, rcx
	cmp rsi, 0x0
	jl .return
	cmp rcx, 0x0
	je .return
	.loop_byte:
		xor rax,rax
		cmp r8, rsi
		je .return
		mov rbx, rdi
		add rdi, r8
		push rsi
		pop r9
		push rdx
		pop rsi
		push rcx
		pop rdx
		call _ft_memcmp
		push rdx
		pop rcx
		push rsi
		pop rdx
		push r9
		pop rsi
		push rbx
		pop rdi
		cmp rax, 0x0
		je .found
		inc r8
	jmp .loop_byte
	.found:
		mov rax, rdi
		add rax, r8
	.return:
		add rsi, rcx

	pop rbx
	pop r9
	pop r8
ret

_ft_strcmp: ; (string rdi, string rsi)
	push rdx

	call _ft_strlen
	push rax
	pop rdx
	push rdi
	push rsi
	pop rdi
	call _ft_strlen
	push rdi
	pop rsi
	pop rdi
	cmp rax, rdx
	je .continue
	inc rdx
	.continue:
	call _ft_memcmp

	pop rdx
ret

_ft_strcpy: ; (string rdi, string rsi)
	push rdx

	push rdi
	pop rdx
	push rsi
	pop rdi
	call _ft_strlen
	push rdi
	pop rsi
	push rdx
	pop rdi
	push rax
	pop rdx
	inc rdx
	call _ft_memcpy

	pop rdx
ret

_ft_memcpy: ; (string rdi, string rsi, size_t rdx)
	push rcx

	xor rax, rax
	xor rcx, rcx
	.loop_byte:
		cmp rcx, rdx
		je .return
		mov al, [rsi + rcx]
		mov [rdi + rcx], al
		inc rcx
	jmp .loop_byte
	.return:
		mov rax, rdi

	pop rcx
ret