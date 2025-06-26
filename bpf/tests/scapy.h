/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#define SCAPY_BUF(NAME) __scapy_buf_##NAME
#define __SCAPY_BUF_BYTES(NAME) __SCAPY_BUF_##NAME##_BYTES
#define SCAPY_DEF_BUF(NAME, ...) \
	const __u8 SCAPY_BUF(NAME) [] = __SCAPY_BUF_BYTES(NAME)
#define SCAPY_PKT_BUILDER(BUILDER, NAME)			 \
	do {							 \
		if(!pktgen__push_data(&BUILDER, (void *) & SCAPY_BUF(NAME), \
				      sizeof(SCAPY_BUF(NAME))))	 \
			return TEST_ERROR;			 \
	} while(0)


#include ".scapy_bufs.h"
