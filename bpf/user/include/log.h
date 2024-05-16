/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef BPF_USPACE_LOG_H
#define BPF_USPACE_LOG_H

#include <stdio.h>

#ifdef __LIB_DBG__
	#error Wrong order of inclusion. Make sure log.h is included before <lib/dbg.h>
#endif //__LIB_DBG__
#include <lib/dbg.h>

#define cilium_dbg mock_cilium_dbg
#define cilium_dbg2 mock_cilium_dbg2
#define cilium_dbg3 mock_cilium_dbg3

static inline void mock_cilium_dbg(struct __ctx_buff *ctx, __u8 type,
				__u32 arg1, __u32 arg2)
{
	fprintf(stderr, "[DBG] ctx: %p, type: %d, arg1: %d, arg2: %d\n",
						ctx, type, arg1, arg2);
}

static inline void _mock_cilium_dbgX(int level, struct __ctx_buff *ctx,
				__u8 type, __u32 arg1, __u32 arg2,
				__u32 arg3)
{

	fprintf(stderr, "[DBG%d] ctx: %p, type: %d, arg1: %d, arg2: %d, arg3: %d\n",
						level, ctx,
						type, arg1, arg2, arg3);
}

static inline void mock_cilium_dbg2(struct __ctx_buff *ctx, __u8 type,
				__u32 arg1, __u32 arg2, __u32 arg3)
{
	_mock_cilium_dbgX(2, ctx, type, arg1, arg2, arg3);
}

static inline void mock_cilium_dbg3(struct __ctx_buff *ctx, __u8 type,
				__u32 arg1, __u32 arg2, __u32 arg3)
{
	_mock_cilium_dbgX(3, ctx, type, arg1, arg2, arg3);
}

#endif //BPF_USPACE_LOG_H
