
; Dark Slayer Mutation Engine v1.0
;     Written by Dark Slayer in Taiwan

DSME_GEN SEGMENT
         ASSUME  CS:DSME_GEN,DS:DSME_GEN
         ORG     0100h

MSG_ADDR EQU     OFFSET MSG-OFFSET PROC_START-0005h

         EXTRN   DSME:NEAR,DSME_END:NEAR

                      ; �H�U�{���A���F�n�`�N���a�観�`�ѡA�䥦�����ۤv��s
                      ; you may get some information as following remarks
                      ;

START:
         MOV     AH,09h
         MOV     DX,OFFSET DG_MSG
         INT     21h

         MOV     AX,OFFSET DSME_END+000Fh ; ���{�� + DSME+000Fh ���᪺��}
                                   ; �Y�� 0100h �h�������{�� + DSME ������
                                   ; This program + DSME+000Fh address
                                   ; Minus 0100h = this program + DSME
                                   ; lengh
         MOV     CL,04h
         SHR     AX,CL
         MOV     BX,CS
         ADD     BX,AX

         MOV     ES,BX                   ; �] ES �Ψө�ѽX�{���M�Q�s�X���
                                                ; �ѽX�{���̤j�� 1024 Bytes
                                ; �Y�Φb�`�n�{���ɡA�h���`�N���t���O����j�p
                                ; Setting ES to put decryptor and encrypted
                                ; code.
                                ; Decryptor maxium is 1024 bytes
                                ; You should notice the allocation of memory
                                ; size when you use DSME in resident mode.


         MOV     CX,50
DG_L0:
         PUSH    CX
         MOV     AH,3Ch
         XOR     CX,CX
         MOV     DX,OFFSET FILE_NAME
         INT     21h
         XCHG    BX,AX

         MOV     BP,0100h                                ; �ѽX�{��������}
                                       ; �ΨӼg�r�ɫh�̱��P�V�ɮפ��j�p�ӳ]
                                       ; Offset where the decryption routine
                                       ; will be executed
                                       ; It depends on which kinds of files
                                       ; COM or EXE?

         MOV     CX,OFFSET PROC_END-OFFSET PROC_START    ; �Q�s�X�{��������
                                                         ; encrypted code
                                                         ; lengh

         MOV     DX,OFFSET PROC_START         ; DS:DX -> �n�Q�s�X���{����}
                                              ; DS:DX -> Encrypted code's
                                              ;          address

         PUSH    BX                                      ; �O�s File handle
                                                         ; keep File handle

         MOV     BL,00h                                          ; COM �Ҧ�
                                                                 ; COM mode

         CALL    DSME

         POP     BX

         MOV     AH,40h        ; ��^�� DS:DX = �ѽX�{�� + �Q�s�X�{������}
         INT     21h     ; CX = �ѽX�{�� + �Q�s�X�{�������סA�䥦�Ȧs������
                         ;  When returning from DSME,
                         ;  DS:DX = decryptor + encrypted code's address
                         ;  CX = lengh of decryptor + encrypted code
                         ; Other registers won't be changed.

         MOV     AH,3Eh
         INT     21h

         PUSH    CS
         POP     DS                                          ; �N DS �]�^��
                                                             ; restore DS

         MOV     BX,OFFSET FILE_NUM
         INC     BYTE PTR DS:[BX+0001h]
         CMP     BYTE PTR DS:[BX+0001h],'9'
         JBE     DG_L1
         INC     BYTE PTR DS:[BX]
         MOV     BYTE PTR DS:[BX+0001h],'0'
DG_L1:
         POP     CX
         LOOP    DG_L0
         MOV     AH,4Ch
         INT     21h

FILE_NAME DB     '000000'
FILE_NUM DB      '00.COM',00h

DG_MSG   DB      'Generates 50 DSME encrypted test files.',0Dh,0Ah,'$'

PROC_START:
         MOV     AH,09h
         CALL    $+0003h
         POP     DX
         ADD     DX,MSG_ADDR
         INT     21h
         INT     20h
MSG      DB      'this is <DSME> test file.$'
PROC_END:

DSME_GEN ENDS
         END     START
