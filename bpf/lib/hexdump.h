/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include "dbg.h"

#define HD_WORD_SIZE 16
#define HD_MAX_WORDS (256/HD_WORD_SIZE)
#define HD_ASCII_NUM0  0x30
#define HD_ASCII_SPACE 0x20
#define HD_ASCII_TILDE 0x7E

/* Dump (at most) the first 256 bytes of packet tcpdump-style */
static __always_inline
void hexdump(const struct __ctx_buff *ctx, __u16 len)
{
#if defined(DEBUG) && !defined(__PKT_HEXDUMP_DISABLE__)
	return;
#endif /* DEBUG && !__PKT_HEXDUMP_DISABLE__ */

	int i, j;
	__u8 byte, *aux;
	char hex_buf[HD_WORD_SIZE*3 + 1] = {0};
	char str_buf[HD_WORD_SIZE + 1] = {0};

	/* Clamp */
	len = (len > HD_MAX_WORDS*HD_WORD_SIZE)? HD_MAX_WORDS*HD_WORD_SIZE : len;

	aux = (__u8*)ctx_data(ctx);
	if ((aux + len) > (__u8*)ctx_data_end(ctx))
		return;

	printk("[%p] pkt_len: %u", ctx, ctx_full_len(ctx));
#pragma unroll
	for (i = 0; i < HD_MAX_WORDS; ++i) {
#pragma unroll
		for(j = 0; j < HD_WORD_SIZE; ++j) {
			if ((i*HD_WORD_SIZE + j) > len)
				break;

			byte = aux[i*HD_WORD_SIZE + j];

			hex_buf[j*3] =   (byte & 0x0F) + HD_ASCII_NUM0;
			hex_buf[j*3+1] = (byte & 0xF0 >> 4) + HD_ASCII_NUM0;
			hex_buf[j*3+2] = HD_ASCII_SPACE;

			if (byte >= HD_ASCII_SPACE && byte <= HD_ASCII_TILDE)
				str_buf[j] = byte;
			else
				str_buf[j] = '.';
		}

		if (j != HD_WORD_SIZE)
			hex_buf[j*3] = str_buf[j] = '\0';

		printk("[%p] %s %s\n", ctx, hex_buf, str_buf);

		if (j != HD_WORD_SIZE)
			break;
	}
}
