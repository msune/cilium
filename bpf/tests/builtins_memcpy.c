// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <node_config.h>

#include "builtin_test.h"

#define test___builtin_memcpy_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 __z[len] __align_stack_8;					\
		__bpf_memset_builtin(__x, 0, len);				\
		__fill_rnd(__y, len);						\
		__bpf_memcpy_builtin(__z, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memcpy(__x, __y, len);					\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, len));				\
	} while (0)

CHECK("tc", "builtin_memcpy")
int test_builtin_memcpy(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memcpy 128 > builtin_memcpy.h */
	#include "builtin_memcpy.h"

	test_finish();
}
