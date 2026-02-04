// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include <node_config.h>

#include "builtin_test.h"

/* Same as test___builtin_memcpy_single(). */
#define test___builtin_memmove1_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 __z[len] __align_stack_8;					\
		__bpf_memset_builtin(__x, 0, len);				\
		__fill_rnd(__y, len);						\
		__bpf_memcpy_builtin(__z, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memmove_bwd(__x, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, len));				\
	} while (0)

/* Overlapping with src == dst. */
#define test___builtin_memmove2_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 *__p_x = (__u8 *)__x;					\
		__u8 *__p_y = (__u8 *)__y;					\
		const __u32 off = 0;						\
		__fill_cnt(__x, len);						\
		__bpf_memcpy_builtin(__y, __x, len);				\
		__bpf_memcpy_builtin(__p_y + off, __x, len - off);		\
		barrier_data(__x);						\
		__bpf_memmove(__p_x + off, __x, len - off);			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

/* Overlapping with src < dst. */
#define test___builtin_memmove3_single(len)					\
	do {									\
		__u8 __x[len] __align_stack_8;					\
		__u8 __y[len] __align_stack_8;					\
		__u8 *__p_x = (__u8 *)__x;					\
		__u8 *__p_y = (__u8 *)__y;					\
		__u32 off = (len / 2) & ~1U;					\
		if (len >= 8)							\
			off &= ~7U;						\
		else if (len >= 4)						\
			off &= ~3U;						\
		__fill_cnt(__x, len);						\
		__bpf_memcpy_builtin(__y, __x, len);				\
		__bpf_memcpy_builtin(__p_y + off, __x, len - off);		\
		barrier_data(__x);						\
		__bpf_memmove(__p_x + off, __x, len - off);			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

/* Overlapping with src > dst. */
#define test___builtin_memmove4_single(len)					\
	do {									\
		__u8 __xbuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 __ybuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 *__x = __xbuf + ALIGN8_OFFSET(len);			\
		__u8 *__y = __ybuf + ALIGN8_OFFSET(len);			\
		__u8 *__p_x = (__u8 *)__x;					\
		const __u32 off = (len / 2) & ~7U;				\
		__fill_cnt(__x, len);						\
		__bpf_memcpy_builtin(__y, __x, len);				\
		__bpf_memcpy_builtin(__y, __p_x + off, len - off);		\
		barrier_data(__x);						\
		__bpf_memmove(__x, __p_x + off, len - off);			\
		barrier_data(__x);						\
		barrier_data(__y);						\
		assert(!__cmp_mem(__x, __y, len));				\
	} while (0)

/* Same as test___builtin_memmove1_single(), but fwd. */
#define test___builtin_memmove5_single(len)					\
	do {									\
		__u8 __xbuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 __ybuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 __zbuf[ROUNDUP8(len)] __align_stack_8;			\
		__u8 *__x = __xbuf + ALIGN8_OFFSET(len);			\
		__u8 *__y = __ybuf + ALIGN8_OFFSET(len);			\
		__u8 *__z = __zbuf + ALIGN8_OFFSET(len);			\
		__bpf_memset_builtin(__x, 0, len);				\
		__fill_rnd(__y, len);						\
		__bpf_memcpy_builtin(__z, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__y);						\
		__bpf_memmove_fwd(__x, __y, len);				\
		barrier_data(__x);						\
		barrier_data(__z);						\
		assert(!__cmp_mem(__x, __z, len));				\
	} while (0)

/**
 * Note the test is intentionally split in I and II due to a CLANG
 * bug (possibly out of jump labels), see commit history and
 * PR#41017 for more details.
 */
CHECK("tc", "builtin_memmove")
int test_builtin_memmove(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memmove1 128  > builtin_memmove.h */
	/* ./builtin_gen memmove2 128 >> builtin_memmove.h */
	/* ./builtin_gen memmove3 128 >> builtin_memmove.h */
	#include "builtin_memmove.h"

	test_finish();
}

CHECK("tc", "builtin_memmove2")
int test_builtin_memmove2(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	/* ./builtin_gen memmove4 128 > builtin_memmove2.h */
	/* ./builtin_gen memmove5 128 >> builtin_memmove2.h */
	#include "builtin_memmove2.h"

	test_finish();
}
