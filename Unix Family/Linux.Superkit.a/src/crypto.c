/*
 * $Id: crypto.c, ehrm, very, very lame crypto stuff
 */

#define CONFIG_H

#include "stuff.h"
#include "sk.h"
#include "crypto.h"
#include "sha1.h"
#include "strasm.h"

/* create hash from some bytes */
void	hash160(void *p, int len, struct hash *out)
{
	SHA1_CTX	context;

	SHA1Init(&context);
	SHA1Update(&context, p, len);
	SHA1Final((uchar *) out, &context);
}

/* sign client -- hash pwd & cookie */
void	sign(ushort port, struct auth *a, struct hash *pwd)
{
	hash160(pwd, sizeof(*pwd), &a->hash);
	a->port = port;
}

/* init, ehrm, "encryption/decryption" */
void	crypt_init(struct hash *key, crypt_ctx *ctx)
{
	memcpy(ctx->key, key, sizeof(*key));
	ctx->off = 0;
}


/* encrypt ONE byte */
inline	uchar encrypt_byte(crypt_ctx *ctx, uchar byte)
{
	uchar	res;

	res = byte ^ ctx->key[ctx->off];
	ctx->key[ctx->off] += byte;
	ctx->off++;
	if (ctx->off == sizeof(ctx->key)) {
		hash160(ctx->key, sizeof(ctx->key),
			(struct hash *) ctx->key);
		ctx->off = 0;
	}
	return res;
}

/* decrypt ONE byte */
inline	uchar decrypt_byte(crypt_ctx *ctx, uchar byte)
{
	uchar	res;

	res = byte ^ ctx->key[ctx->off];
	ctx->key[ctx->off] += res;
	ctx->off++;
	if (ctx->off == sizeof(ctx->key)) {
		hash160(ctx->key, sizeof(ctx->key),
			(struct hash *) ctx->key);
		ctx->off = 0;
	}
	return res;
}

/* encrypt any amount of bytes */
void	encrypt_data(crypt_ctx *ctx, uchar *data, int len)
{
	for (; len; len--, data++)
		*data = encrypt_byte(ctx, *data);
}

/* decrypt any amount of bytes */
void	decrypt_data(crypt_ctx *ctx, uchar *data, int len)
{
	for (; len; len--, data++)
		*data = decrypt_byte(ctx, *data);
}

int	encrypt_write(int fd, uchar *data, int len, crypt_ctx *ctx)
{
	uchar	c;
	int	i, cnt;
	for (cnt = 0; cnt < len; cnt++, data++) {
		c = encrypt_byte(ctx, *data);
		i = write(fd, &c, 1);
		if (i < 0) return -1;
	}
	return cnt;
}

int	decrypt_read(int fd, uchar *data, int len, crypt_ctx *ctx)
{
	uchar	c;
	int	i, cnt;
	for (cnt = 0; cnt < len; cnt++, data++) {
		i = read(fd, &c, 1);
		if (i < 0) return -1;
		*data = decrypt_byte(ctx, c);
	}
	return cnt;
}
