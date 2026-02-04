// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <node_config.h>

#include "builtin_test.h"

#define test___builtin_memcmp_single(len)					\
	do {									\
		bool res, cor;							\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__fill_rnd(__x, len);						\
		__cpy_mem(__y, __x, len);					\
		cor = __corrupt_mem(__y, len);					\
		barrier_data(__x);						\
		barrier_data(__y);						\
		res = __bpf_memcmp(__x, __y, len);				\
		assert(cor == res);						\
	} while (0)

CHECK("tc", "builtin_memcmp")
int test_builtin_memcmp(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	int i;

	for (i = 0; i < BUILTIN_MEMCMP_RUNS; ++i) {
		/* ./builtin_gen memcmp 128 > builtin_memcmp.h */
		#include "builtin_memcmp.h"
	}

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
