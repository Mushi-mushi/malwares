/*
 * $Id: crypto.h, ehrm ... crypto ... ehrm ehrm stuff ;)
 */

#ifndef CRYPTO_H
#define CRYPTO_H

/* md5/sha1 160 bit hash */
struct hash {
	uchar	val[20];
}  __attribute__ ((packed));

/* authentication structure transferred over net */
struct auth {
	struct	hash hash;
	ushort	port;
} __attribute__ ((packed));

typedef struct {
	uchar	key[20];
	ulong	off;
} crypt_ctx;


extern void	hash160(void *p, int len, struct hash *out);
extern void	sign(ushort port, struct auth *a, struct hash *pwd);
extern void	crypt_init(struct hash *key, crypt_ctx *ctx);
extern void	encrypt_data(crypt_ctx *ctx, uchar *data, int len);
extern void	decrypt_data(crypt_ctx *ctx, uchar *data, int len);
extern int	encrypt_write(int fd, uchar *data, int len, crypt_ctx *ctx);
extern int	decrypt_read(int fd, uchar *data, int len, crypt_ctx *ctx);
extern uchar	encrypt_byte(crypt_ctx *ctx, uchar byte);
extern uchar	decrypt_byte(crypt_ctx *ctx, uchar byte);


#endif
