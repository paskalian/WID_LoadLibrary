.code
ZwSystemDebugControl proc
 
	mov r10, rcx
	mov eax, 1CDh
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh
 
ZwSystemDebugControl endp

NtCreateSection proc

	mov r10, rcx
	mov eax, 4Ah
	test byte ptr [7FFE0308h], 1 ; KUSER_SHARED_DATA.SystemCall
	jnz short SYSCALL_DEFINED
	syscall
	ret
SYSCALL_DEFINED:
	int 2Eh

NtCreateSection endp
end

