/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#include "lib/common.h"

/**
 * For the reader, memcmp() tests use rand() to corrupt memory, so there is
 * 50% chance. The # of runs assures there is a reasonable (~99.3%) that
 * not all of the runs are the same (corrupt or non-corrupt).
 *
 * NOTE: increasing this much further can reach the max. instruction limit
 * TODO: to move these iterations to the Makefile instead of the test itself
 */
#define BUILTIN_MEMCMP_RUNS 8

/* Manual slow versions, but doesn't matter for the sake of testing here.
 * Mainly to make sure we don't end up using the overridden builtin.
 */
static __always_inline __u32 __cmp_mem(const void *x, const void *y, __u32 len)
{
	const __u8 *x8 = x, *y8 = y;
	__u32 i;

	for (i = 0; i < len; i++) {
		if (x8[i] != y8[i])
			return 1;
	}

	return 0;
}

static __always_inline void __cpy_mem(void *d, void *s, __u32 len)
{
	__u8 *d8 = d, *s8 = s;
	__u32 i;

	for (i = 0; i < len; i++)
		d8[i] = s8[i];
}

static void __fill_rnd(void *buff, __u32 len)
{
	__u8 *dest = buff;
	__u32 i;

	for (i = 0; i < len; i++)
		dest[i] = (__u8)get_prandom_u32();
}

static __always_inline bool __corrupt_mem(void *d, __u32 len)
{
	bool corrupted = get_prandom_u32() & 1;
	__u32 pos = get_prandom_u32() % len;
	__u32 roundup_len;
	__u8 *d8 = d;

	/* When len is not a power of two, the verifier doesn't see boundaries
	 * of pos after the modulo operation. Apply an additional bitmask that
	 * doesn't change the value, but restricts len to the closest power of
	 * two.
	 */
	roundup_len = 1 << (32 - __builtin_clz(len - 1));
	asm volatile("%0 &= %1" : "+r"(pos) : "r"(roundup_len - 1));

	/* Compute d8 += pos in asm, because Clang optimizes it to a bitwise OR
	 * when it knows that d is aligned and len is 2, and the verifier
	 * forbids bitwise OR on pointers.
	 */
	asm volatile("%0 += %1" : "+r"(d8) : "r"(pos));

	*d8 += corrupted;

	return corrupted;
}

static __maybe_unused void __fill_cnt(void *buff, __u32 len)
{
	__u8 *dest = buff;
	__u32 i;
	__u8 cnt = 0;

	for (i = 0; i < len; i++)
		dest[i] = cnt++;
}

#define ROUNDUP8(val) (((val) + 7) & ~7U)
#define ALIGN8_OFFSET(val) ((8 - (val) & 7) & 7)
