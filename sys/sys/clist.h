/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)clist.h	8.1 (Berkeley) 6/4/93
 * $FreeBSD: src/sys/sys/clist.h,v 1.10 1999/12/29 04:24:38 peter Exp $
 * $DragonFly: src/sys/sys/clist.h,v 1.5 2006/05/20 02:42:13 dillon Exp $
 */

#ifndef _SYS_CLIST_H_
#define _SYS_CLIST_H_

#ifndef _SYS_TYPES_H_
#include <sys/types.h>
#endif

#define CBLOCK	128		/* Clist block size, must be a power of 2. */
#define CBQSIZE	(CBLOCK/NBBY)	/* Quote bytes/cblock - can do better. */
				/* Data chars/clist. */
#define CBSIZE	(CBLOCK - sizeof(struct cblockhead) - CBQSIZE)
#define CROUND	(CBLOCK - 1)	/* Clist rounding. */

struct cblockhead {
	struct cblock *ch_next;
	int	ch_magic;
};

#define CLIST_MAGIC_FREE	0x434c0102
#define CLIST_MAGIC_USED	0x434c8182

struct cblock {
	struct cblockhead c_head;		/* header */
	unsigned char c_quote[CBQSIZE];		/* quoted characters */
	unsigned char c_info[CBSIZE];		/* characters */
};

#ifdef _KERNEL
extern	struct cblock *cfree;
extern	int cfreecount;
#endif

#endif
