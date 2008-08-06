/**
 * @file crypt.c
 *
 * purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * QQ encryption algorithm
 * Convert from ASM code provided by PerlOICQ
 * 
 * Puzzlebird, Nov-Dec 2002
 */

/* Notes: (QQ uses 16 rounds, and modified something...)

IN : 64  bits of data in v[0] - v[1].
OUT: 64  bits of data in w[0] - w[1].
KEY: 128 bits of key  in k[0] - k[3].

delta is chosen to be the real part of 
the golden ratio: Sqrt(5/4) - 1/2 ~ 0.618034 multiplied by 2^32. 

0x61C88647 is what we can track on the ASM codes.!!
*/

#include <string.h>

#include "crypt.h"
#include "debug.h"

/* 1, fixed alignment problem, when compiled on different platform
 * 2, whether we need core debug
 * 20070717, s3e */
#if 0 
#define CORE_DEBUG
#endif

/********************************************************************
 * encryption 
 *******************************************************************/

/* Tiny Encryption Algorithm (TEA) */
static void qq_encipher(guint32 *const v, const guint32 *const k, guint32 *const w)
{
	register guint32
		y = g_ntohl(v[0]), 
		 z = g_ntohl(v[1]), 
		 a = g_ntohl(k[0]), 
		 b = g_ntohl(k[1]), 
		 c = g_ntohl(k[2]), 
		 d = g_ntohl(k[3]), 
		 n = 0x10, 
		 sum = 0, 
		 delta = 0x9E3779B9;	/*  0x9E3779B9 - 0x100000000 = -0x61C88647 */

	while (n-- > 0) {
		sum += delta;
		y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
	}

	w[0] = g_htonl(y);
	w[1] = g_htonl(z);
}

/* it can be the real random seed function */
/* override with number, convenient for debug */
#ifdef XDEBUG
static gint rand(void) {	
	return 0xdead; 
}
#else
#include <stdlib.h>
#endif

/* 64-bit blocks and some kind of feedback mode of operation */
static inline void encrypt_block(guint8 *plain, guint8 *plain_pre_8, guint8 **crypted, 
		guint8 **crypted_pre_8, const guint8 *const key, gint *count, 
		gint *pos_in_block, gint *is_header) 
{
	/* loop it */
	int j;
	/* ships in encipher */
	guint32 ptr_p[2];	/* 64 bits, guint32[2] */
	guint32 ptr_k[4];	/* 128 bits, guint32[4] */
	guint32 ptr_c[2];	/* 64 bits, guint32[2] */

	/* prepare input text */
#ifdef CORE_DEBUG
	purple_debug(PURPLE_DEBUG_ERROR, "QQ_CORE_DEBUG",
		"!we are in encrypt_block! *pos_in_block comes: %d, *is_header comes: %d\n",
		*pos_in_block, *is_header);
#endif
	for(j = 0; j < 8; j++) {
#ifdef CORE_DEBUG
		purple_debug(PURPLE_DEBUG_INFO, "QQ_CORE_DEBUG",
			"plain[%d]: 0x%02x, plain_pre_8[%d]: 0x%02x\n",
			j, plain[j], j, plain_pre_8[j]);
#endif
		if (!*is_header) {
#ifdef CORE_DEBUG
			purple_debug(PURPLE_DEBUG_INFO, "QQ_CORE_DEBUG",
				"(*crypted_pre_8 + %d): 0x%02x\n",
				j, *(*crypted_pre_8 + j));
#endif
			plain[j] ^= (*(*crypted_pre_8 + j));
#ifdef CORE_DEBUG
			purple_debug(PURPLE_DEBUG_INFO, "QQ_CORE_DEBUG",
				"NOW plain[%d]: 0x%02x\n",
				j, plain[j]);
#endif
		} else {
			plain[j] ^= plain_pre_8[j];
#ifdef CORE_DEBUG
			purple_debug(PURPLE_DEBUG_INFO, "QQ_CORE_DEBUG",
				"NOW plain[%d]: 0x%02x\n",
				j, plain[j]);
#endif
		}
	}

	g_memmove(ptr_p, plain, 8);
	g_memmove(ptr_k, key, 16);
	g_memmove(ptr_c, *crypted, 8);

	/* encrypt it */
	qq_encipher(ptr_p, ptr_k, ptr_c);
	
	g_memmove(plain, ptr_p, 8);
	g_memmove(*crypted, ptr_c, 8);

	for(j = 0; j < 8; j++) {
#ifdef CORE_DEBUG
		purple_debug(PURPLE_DEBUG_INFO, "QQ_CORE_DEBUG",
			"j: %d, *(*crypted + %d): 0x%02x, plain_pre_8[%d]: 0x%02x\n",
			j, j, *(*crypted + j), j, plain_pre_8[j]);
#endif
		(*(*crypted + j)) ^= plain_pre_8[j];
#ifdef CORE_DEBUG
		purple_debug(PURPLE_DEBUG_INFO, "QQ_CORE_DEBUG",
			"NOW *(*crypted + [%d]): 0x%02x\n",
			j, *(*crypted + j));
#endif
	}
	
	memcpy(plain_pre_8, plain, 8);	/* prepare next */

	*crypted_pre_8 = *crypted;	/* store position of previous 8 byte */
	*crypted += 8;			/* prepare next output */
	*count += 8;			/* outstrlen increase by 8 */
	*pos_in_block = 0;		/* back to start */
	*is_header = 0;			/* and exit header */
}					/* encrypt_block */

void qq_encrypt(const guint8 *const instr, gint instrlen, 
		const guint8 *const key, 
		guint8 *outstr, gint *outstrlen_ptr)
{
	guint8 plain[8],		/* plain text buffer */
		plain_pre_8[8],		/* plain text buffer, previous 8 bytes */
		*crypted,		/* crypted text */
		*crypted_pre_8;		/* crypted text, previous 8 bytes */
	const guint8 *inp;		/* current position in instr */
	gint pos_in_block = 1,		/* loop in the byte */
		is_header = 1,		/* header is one byte */
		count = 0,		/* number of bytes being crypted */
		padding = 0;		/* number of padding stuff */

	pos_in_block = (instrlen + 0x0a) % 8;	/* header padding decided by instrlen */
	if (pos_in_block)
		pos_in_block = 8 - pos_in_block;

	/* initialization vector */
	plain[0] = (rand() & 0xf8) | pos_in_block;
	memset(plain + 1, rand() & 0xff, pos_in_block++);

	memset(plain_pre_8, 0x00, sizeof(plain_pre_8));

	crypted = crypted_pre_8 = outstr;

	padding = 1;		/* pad some stuff in header */
	while (padding <= 2) {	/* at most two bytes */
		if (pos_in_block < 8) {
			plain[pos_in_block++] = rand() & 0xff;
			padding++;
		}
		if (pos_in_block == 8) {
			encrypt_block(plain, plain_pre_8, &crypted, &crypted_pre_8, 
					key, &count, &pos_in_block, &is_header);
		}
	}

	inp = instr;
	while (instrlen > 0) {
		if (pos_in_block < 8) {
			plain[pos_in_block++] = *(inp++);
			instrlen--;
		}
		if (pos_in_block == 8) {
			encrypt_block(plain, plain_pre_8, &crypted, &crypted_pre_8, 
					key, &count, &pos_in_block, &is_header);
		}
	}

	padding = 1;		/* pad some stuff in tail */
	while (padding <= 7) {	/* at most seven bytes */
		if (pos_in_block < 8) {
			plain[pos_in_block++] = 0x00;
			padding++;
		}
		if (pos_in_block == 8) {
			encrypt_block(plain, plain_pre_8, &crypted, &crypted_pre_8, 
					key, &count, &pos_in_block, &is_header);
		}
	}

	*outstrlen_ptr = count;
}


/******************************************************************** 
 * decryption 
 ********************************************************************/

static void qq_decipher(guint32 *const v, const guint32 *const k, guint32 *const w)
{
	register guint32
		y = g_ntohl(v[0]), 
		z = g_ntohl(v[1]), 
		a = g_ntohl(k[0]), 
		b = g_ntohl(k[1]), 
		c = g_ntohl(k[2]), 
		d = g_ntohl(k[3]), 
		n = 0x10, 
		sum = 0xE3779B90,	/* why this ? must be related with n value */
		delta = 0x9E3779B9;

	/* sum = delta<<5, in general sum = delta * n */
	while (n-- > 0) {
		z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
		y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
		sum -= delta;
	}

	w[0] = g_htonl(y);
	w[1] = g_htonl(z);
}

static gint decrypt_block(const guint8 **crypt_buff, const gint instrlen, 
		const guint8 *const key, gint *context_start, 
		guint8 *decrypted, gint *pos_in_block)
{
	/* loop */
	int i;
	/* ships in decipher */
	guint32 ptr_v[2];
	guint32 ptr_k[4];

	if (*context_start == instrlen)
		return 1;

	for(i = 0; i < 8; i++) {
		decrypted[i] ^= (*(*crypt_buff + i));
	}
	
	g_memmove(ptr_v, decrypted, 8);
	g_memmove(ptr_k, key, 16);

	qq_decipher(ptr_v, ptr_k, ptr_v);

	g_memmove(decrypted, ptr_v, 8);

	*context_start += 8;
	*crypt_buff += 8;
	*pos_in_block = 0;

	return 1;
}

/* return 0 if failed, 1 otherwise */
gint qq_decrypt(const guint8 *const instr, gint instrlen, 
		const guint8 *const key,
		guint8 *outstr, gint *outstrlen_ptr)
{
	guint8 decrypted[8], m[8], *outp;
	const guint8 *crypt_buff, *crypt_buff_pre_8;
	gint count, context_start, pos_in_block, padding;
	/* ships */
	guint32 ptr_instr[2];
	guint32 ptr_key[4];
	guint32 ptr_decr[2];

	/* at least 16 bytes and %8 == 0 */
	if ((instrlen % 8) || (instrlen < 16)) { 
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", 
			"Ciphertext len is either too short or not a multiple of 8 bytes, read %d bytes\n", 
			instrlen);
		return 0;
	}
	g_memmove(ptr_instr, instr, 8);
	g_memmove(ptr_key, key, 16);
	g_memmove(ptr_decr, decrypted, 8);

	qq_decipher(ptr_instr, ptr_key, ptr_decr);

	g_memmove(decrypted, ptr_decr, 8);

	pos_in_block = decrypted[0] & 0x7;
	count = instrlen - pos_in_block - 10;	/* this is the plaintext length */
	/* return if outstr buffer is not large enough or error plaintext length */
	if (*outstrlen_ptr < count || count < 0) {
		purple_debug(PURPLE_DEBUG_ERROR, "QQ", "Buffer len %d is less than real len %d", 
			*outstrlen_ptr, count);
		return 0;
	}

	memset(m, 0, 8);
	crypt_buff_pre_8 = m;
	*outstrlen_ptr = count;	/* everything is ok! set return string length */

	crypt_buff = instr + 8;	/* address of real data start */
	context_start = 8;	/* context is at the second block of 8 bytes */
	pos_in_block++;		/* start of paddng stuff */

	padding = 1;		/* at least one in header */
	while (padding <= 2) {	/* there are 2 byte padding stuff in header */
		if (pos_in_block < 8) {	/* bypass the padding stuff, it's nonsense data */
			pos_in_block++;
			padding++;
		}
		if (pos_in_block == 8) {
			crypt_buff_pre_8 = instr;
			if (!decrypt_block(&crypt_buff, instrlen, key, 
						&context_start, decrypted, &pos_in_block)) {
				purple_debug(PURPLE_DEBUG_ERROR, "QQ", "decrypt every 8 bytes error A");
				return 0;
			}
		}
	}

	outp = outstr;
	while (count != 0) {
		if (pos_in_block < 8) {
			*outp = crypt_buff_pre_8[pos_in_block] ^ decrypted[pos_in_block];
			outp++;
			count--;
			pos_in_block++;
		}
		if (pos_in_block == 8) {
			crypt_buff_pre_8 = crypt_buff - 8;
			if (!decrypt_block(&crypt_buff, instrlen, key, 
						&context_start, decrypted, &pos_in_block)) {
				purple_debug(PURPLE_DEBUG_ERROR, "QQ", "decrypt every 8 bytes error B");
				return 0;
			}
		}
	}

	for (padding = 1; padding < 8; padding++) {
		if (pos_in_block < 8) {
			if (crypt_buff_pre_8[pos_in_block] ^ decrypted[pos_in_block])
				return 0;
			pos_in_block++;
		}
		if (pos_in_block == 8) {
			crypt_buff_pre_8 = crypt_buff;
			if (!decrypt_block(&crypt_buff, instrlen, key, 
						&context_start, decrypted, &pos_in_block)) {
				purple_debug(PURPLE_DEBUG_ERROR, "QQ", "decrypt every 8 bytes error C");
				return 0;
			}
		}
	}

	return 1;
}
