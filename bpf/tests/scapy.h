/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#define SCAPY_BUF(NAME) __scapy_buf_##NAME
#define __SCAPY_BUF_BYTES(NAME) __SCAPY_BUF_##NAME##_BYTES
#define SCAPY_DEF_BUF(NAME, ...) \
	const __u8 SCAPY_BUF(NAME) [] = __SCAPY_BUF_BYTES(NAME)

/**
* Build packet per scapy definition
*/
static __always_inline
int __scapy_build_pkt(struct __ctx_buff *ctx, const __u8* buffer,
		      const __u32 len)
{
	(void)ctx;
	(void)buffer;
	(void)len;
	return 0;
}


#define scapy_build_pkt(CTX, BUF_NAME) \
			__scapy_build_pkt(CTX, SCAPY_BUF(BUF_NAME), \
					  sizeof( SCAPY_BUF(BUF_NAME) ))

#include ".scapy_bufs.h"
