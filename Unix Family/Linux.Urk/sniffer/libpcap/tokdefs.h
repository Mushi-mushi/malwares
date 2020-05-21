typedef union {
	int i;
	bpf_u_int32 h;
	u_char *e;
	char *s;
	struct stmt *stmt;
	struct arth *a;
	struct {
		struct qual q;
		struct block *b;
	} blk;
	struct block *rblk;
} YYSTYPE;
#define	DST	257
#define	SRC	258
#define	HOST	259
#define	GATEWAY	260
#define	NET	261
#define	MASK	262
#define	PORT	263
#define	LESS	264
#define	GREATER	265
#define	PROTO	266
#define	BYTE	267
#define	ARP	268
#define	RARP	269
#define	IP	270
#define	TCP	271
#define	UDP	272
#define	ICMP	273
#define	IGMP	274
#define	IGRP	275
#define	ATALK	276
#define	DECNET	277
#define	LAT	278
#define	SCA	279
#define	MOPRC	280
#define	MOPDL	281
#define	TK_BROADCAST	282
#define	TK_MULTICAST	283
#define	NUM	284
#define	INBOUND	285
#define	OUTBOUND	286
#define	LINK	287
#define	GEQ	288
#define	LEQ	289
#define	NEQ	290
#define	ID	291
#define	EID	292
#define	HID	293
#define	LSH	294
#define	RSH	295
#define	LEN	296
#define	OR	297
#define	AND	298
#define	UMINUS	299


extern YYSTYPE pcap_lval;
