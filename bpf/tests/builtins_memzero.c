// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <node_config.h>

#include "builtin_test.h"

#define test___builtin_memzero_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__bpf_memset_builtin(__y, 0, len);				\
		__fill_rnd(__x, len);						\
		barrier_data(__x);						\
		__bpf_memzero(__x, len);					\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

CHECK("tc", "builtin_memzero")
int test_builtin_memzero(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memzero 128 > builtin_memzero.h */
	#include "builtin_memzero.h"

	test_finish();
}
