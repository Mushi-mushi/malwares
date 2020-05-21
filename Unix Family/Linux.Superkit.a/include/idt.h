/*
 * $Id: idt.h, structs for playing with IDTs
 */

#ifndef IDT_H
#define IDT_H

struct idtr {
        ushort	limit;
	ulong	base;
} __attribute__ ((packed));

struct idt {
	ushort	off1;
	ushort	sel;
	uchar	none, flags;
	ushort	off2;
} __attribute__ ((packed));

#endif
