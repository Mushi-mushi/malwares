/*
 * Copyright 1990 - 1993, John F. Haugh II
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by John F. Haugh, II
 *      and other contributors.
 * 4. Neither the name of John F. Haugh, II nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN HAUGH AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL JOHN HAUGH OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include "rcsid.h"
RCSID("$Id: encrypt.c,v 1.1.1.1 1996/08/10 07:59:50 marekm Exp $")

#include "prototypes.h"
#include "defines.h"

extern	char	*crypt();
extern char *md5_crypt();

char *
pw_encrypt(clear, salt)
	const char *clear;
	const char *salt;
{
#ifdef HAVE_LIBCRYPT
/* XXX - some systems may have libcrypt which supports only the old
   DES-based algorithm.  We probably want to check (AC_TRY_RUN) to
   see if crypt() in libcrypt supports MD5.  --marekm */
	return crypt(clear, salt);
#else
	static	char	cipher[128];
	char	*cp;
#ifdef SW_CRYPT
	static	int	count;
#endif

#ifdef MD5_CRYPT
	/*
	 * If the salt string from the password file or from crypt_make_salt()
	 * begins with the magic string, use the new algorithm.
	 */
	if (strncmp(salt, "$1$", 3) == 0)
		return md5_crypt(clear, salt);
#endif

#ifdef	SW_CRYPT
	/*
	 * Copy over the salt.  It is always the first two
	 * characters of the string.
	 */

	cipher[0] = salt[0];
	cipher[1] = salt[1];
	cipher[2] = '\0';

	/*
	 * Loop up to ten times on the cleartext password.
	 * This is because the input limit for passwords is
	 * 80 characters.
	 *
	 * The initial salt is that provided by the user, or the
	 * one generated above.  The subsequent salts are gotten
	 * from the first two characters of the previous encrypted
	 * block of characters.
	 */

	for (count = 0;count < 10;count++) {
		cp = crypt (clear, salt);
		if (strlen(cp) != 13)
			return cp;
		strcat (cipher, cp + 2);
		salt = cipher + 11 * count + 2;

		if (strlen (clear) > 8)
			clear += 8;
		else
			break;
	}
#else
	cp = crypt (clear, salt);
	if (strlen(cp) != 13)
		return cp;  /* nonstandard crypt() in libc, better bail out */
	strcpy (cipher, cp);

#ifdef	DOUBLESIZE
	if (strlen (clear) > 8) {
		cp = crypt (clear + 8, salt);
		strcat (cipher, cp + 2);
	}
#endif	/* DOUBLESIZE */
#endif	/* SW_CRYPT */
	return cipher;
#endif  /* HAVE_LIBCRYPT */
}
