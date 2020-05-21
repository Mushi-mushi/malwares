;FICHIER : Lusion_payload.asm
;NOM     : some blobs
;DATE    : 05/10/2003
;VERSION : 1.0

.386
.model flat,STDCALL

Camera          EQU 400
BLOB_LARGEUR    EQU 16                                    
BLOB_HAUTEUR    EQU 12
BLOB_COULEUR    EQU 255

.data

Class:
        style           dd 4003h
        wndproc         dd 0
        classextra      dd 0
        wndextra        dd 0
        instance        dd 0
        icon            dd 0
        cursor          dd 0
        background      dd 1
        menuname        dd 0
        classname       dd 0

rand            dd 45897512h

credits db "Win32.lusion  Coded by kaze[FAT]",0
len_credits equ $ - offset credits -1


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

points          dd 40,40,14
                dd 40,40,-14
                dd -40,40,-14 
                dd 40,-40,-14 
                dd 30,10,20
                dd 0,50,20
                dd -20,-10,-1
                dd 61,16,19

nbr_points equ ($-offset points)/12


Xangle dd 5
Yangle dd 10
Zangle dd 10

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


Xcos dd ?
Xsin dd ?
Ycos dd ?
Ysin dd ?
Zcos dd ?
Zsin dd ?

hwnd            dd ?
hdc1            dd ?
adrord          dd ?
bmp_header      dd ?
bmp_buffer      dd ?

.code

call_ macro x
        extrn x:PROC
        call x
endm

PL_BACKGROUND_COLOR     EQU 0FFFFFFFFh
PL_LARGEUR              EQU 300
PL_HAUTEUR              EQU 300
PL_BPP                  EQU 1
PL_COULEURS             EQU 256

start:  

;============================ REGISTER CLASS ================================
        push 0
        push offset credits
        push offset taille_virus
        push 0
        call_ MessageBoxA
        xor ebx,ebx
        mov wndproc,offset WndProc
        push ebx
        call_ GetModuleHandleA
        mov instance,eax
        mov classname,offset credits
        push PL_BACKGROUND_COLOR
        call_ CreateSolidBrush
        mov background,eax
        push offset Class
        call_ RegisterClassA


;============================ CREATE WINDOW =================================

        xor ebx,ebx
        push ebx                        ;lpvParam
        push instance                   ;Hinstance
        push ebx                        ;Hmenu
        push ebx                        ;Hparentwindow
        push PL_HAUTEUR+25              ;Height
        push PL_LARGEUR                 ;Width
        push 0                          ;y
        push 0                          ;x
        push 80000000h+40000h           ;dwStyle
        lea eax,credits
        push eax                        ;WndName
        push eax                        ;ClassName
        push 8                          ;dwExtStyle
        call_ CreateWindowExA
        test eax,eax
        jz fin

        mov hwnd,eax
        push 1
        push eax
        call_ ShowWindow

        push hwnd
        call_ GetDC
        mov hdc1,eax

        push PL_COULEURS*4+1024+40 + PL_LARGEUR*(PL_HAUTEUR+10)+1024  
        push 40h
        call_ LocalAlloc
        test eax,eax
        jz fin

        mov bmp_header,eax
        mov edi,eax
        add eax,PL_COULEURS*4+1024
        mov bmp_buffer,eax

        mov eax,40
        stosd
        mov eax,PL_LARGEUR
        stosd
        mov eax,PL_HAUTEUR
        stosd
        mov eax,00080001h
        stosd
        add edi,40-16

        xor eax,eax
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
        inc Zangle
        inc Xangle
        add Yangle,3
        call CalcAngles

        mov ecx,nbr_points-1
        lea edi,points
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
        add edi,bmp_buffer
        call Do_blob
        pop edi
        add edi,12
        pop ecx
        loop calcpoints

        call Blur
        
        xor ecx,ecx
        push 00CC0020h
        push ecx
        push bmp_header
        mov eax,bmp_buffer
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
        push hdc1
        call_ StretchDIBits

        push len_credits
        push offset credits
        push PL_HAUTEUR
        push 35
        push hdc1
        call_ TextOutA
        jmp SuperLoop
        
        
fin:    push 0
        call_ ExitProcess








r_range:
push ecx
push edx
mov ecx,eax
mov eax, 214013h
imul dword ptr rand
xor edx, edx
add eax, 2531011h
mov rand, eax
xor edx,edx
div ecx
mov eax,edx
pop edx
pop ecx
ret


WndProc proc 
        pop ebx
        call_ DefWindowProcA
        push ebx
        ret
WndProc endp

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
        mov esi,bmp_buffer
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

GetSinCos proc near
; Needed : bx=angle (0..255)
; Returns: ax=Sin   bx=Cos
        push ecx
        and ebx,0FFh
        mov     al,[SinCos + ebx ]   ; Get sin
        cbw
        cwde
        mov ecx,eax
        add ebx,64
        and ebx,0FFh
        mov     al,[SinCos + ebx]   ; Get cos
        cbw
        cwde
        mov ebx,eax
        mov eax,ecx
        pop ecx
        ret        
GetSinCos ENDP 

CalcAngles proc near
        mov ebx,Zangle
        call GetSinCos
        mov Zcos,ebx
        mov Zsin,eax
        mov ebx,Yangle
        call GetSinCos
        mov Ycos,ebx
        mov Ysin,eax
        mov ebx,Xangle
        call GetSinCos
        mov Xcos,ebx
        mov Xsin,eax
        ret
CalcAngles endp        


rotate_x proc near              ;in/out : ebx=x ecx=y esi=z
; newy= cos(a)*y-sin(a)*z
; newz= sin(a)*y+cos(a)*z
        mov eax,Xcos
        imul ecx
        mov edi,eax
        mov eax,Xsin
        imul esi
        sub edi,eax
        sar edi,7
        push edi                ;newy
        
        mov eax,Xsin
        imul ecx
        mov edi,eax
        mov eax,Xcos
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
        mov eax,Ycos
        imul ebx
        mov edi,eax
        mov eax,Ysin
        imul esi
        add edi,eax
        sar edi,7
        push edi
        
        mov eax,Ycos
        imul esi
        mov edi,eax
        mov eax,Ysin
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
        mov eax,Zcos
        imul ebx
        mov edi,eax
        mov eax,Ysin
        imul ecx
        sub edi,eax
        sar edi,7

        push edi                ;newx
        
        mov eax,Zsin
        imul ebx
        mov edi,eax
        mov eax,Zcos
        imul ecx
        add edi,eax
        mov ecx,edi
        sar ecx,7              ;newy
        pop ebx                 ;newx
        ret
rotate_z endp

Do_blob proc near       ;edi=offset
        pusha
        lea esi,blob
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

virus_len equ $-offset start
taille_virus    db virus_len/10000+48,(virus_len MOD 10000)/1000+48,(virus_len MOD 1000)/100+48,(virus_len MOD 100)/10+48,virus_len MOD 10+48,0
end start
