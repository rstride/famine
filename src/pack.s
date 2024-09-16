%include "constants.inc"
%include "data.inc"

section .text

_global _pack
_global _unpack

_pack: ;(void *rdi) -> ret size + fill rdi
	push r8
	push r10
	push r11
	push r12
	push rbx
	push rcx
	push rdx
	push rsi

	lea rdx, [rel _eof]
	lea r10, [rel _pack_start] ; dictionary = addr
	mov r11, r10; buffer = addr
	sub rdx, r10; size

	xor rcx, rcx; i = 0
	xor r8, r8; l = 0
	.loop_compress:
		cmp rcx, rdx; while (i < size) {
		jge .end_compress
		mov rsi, r10
		sub rsi, r11; len = dictionary - buffer
		cmp rsi, 255; if (len > 255) {
		jle .continue
		add r11, rsi
		sub r11, 255; buffer += len - 255
		mov rsi, r10
		sub rsi, r11; len = dictionary - buffer
		.continue: ; }
		push 1
		pop rbx; k = 1
		xor r12, r12; prev_ret = 0
		.loop_memmem:; while
			cmp rbx, 255
			jge .end_memmem; (k < 255
			mov rax, rbx
			add rax, rcx
			cmp rax, rdx; && i + k < size)
			jge .end_memmem
			push rdi
			push rdx
			push rcx
			mov rdi, r11
			mov rdx, r10
			mov rcx, rbx
			call _ft_memmem; ret = ft_memmem(buffer, len, dictionary, k)
			pop rcx
			pop rdx
			pop rdi
			cmp rax, 0x0; if (!ret) break
			je .end_memmem
			push rax
			pop r12; prev_ret = ret
			inc rbx; k++
		jmp .loop_memmem
		.end_memmem:; }
		dec rbx; k--
		cmp r12, 0x0; if (prev_ret
		je .not_compress_char
		cmp rbx, 4; && k >= 4) {
		jl .not_compress_char
		mov byte[rdi + r8], MAGIC_CHAR; addr[l] = MAGIC_CHAR
		inc r8; l++
		mov rax, r10
		sub rax, r12
		mov byte[rdi + r8], al; addr[l] = dictionary - prev_ret
		inc r8; l++
		mov rax, rbx
		mov byte[rdi + r8], al; addr[l] = k
		inc r8; l++
		jmp .next_loop; }
		.not_compress_char:; else {
		push 1
		pop rbx; k = 1
		mov al, [r10]
		mov byte[rdi + r8], al; addr[l] = *dictionary
		inc r8; l++
	.next_loop:; }
		add r10, rbx; dictionary += k
		add rcx, rbx; i += k
		jmp .loop_compress
	.end_compress: ; }
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

_unpack:; (void *rdi, void *rsi, size_t rdx)
	push r8
	push r9
	push r10
	push r11
	push rcx

	push rdi
	pop r9
	push rsi
	pop r10
	push rdx
	pop r11

	xor rax, rax
	xor rcx, rcx; i
	xor r8, r8; j
	.loop_uncompress:
		cmp rcx, r11
		jge .end_loop
		cmp byte[r10 + rcx], MAGIC_CHAR
		je .uncompress_char
			mov al, [r10 + rcx]
			mov [r9 + r8], al
			inc rcx
			inc r8
		jmp .loop_uncompress
		.uncompress_char:
			mov rdi, r9
			add rdi, r8
			mov al, [r10 + rcx + 1]
			mov rsi, rdi
			sub rsi, rax
			mov al, [r10 + rcx + 2]
			mov rdx, rax
			call _ft_memcpy
			xor rax, rax
			mov al, byte[r10 + rcx + 2]
			add r8, rax
			add rcx, 3
		jmp .loop_uncompress
	.end_loop:
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