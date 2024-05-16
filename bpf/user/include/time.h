/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef BPF_USPACE_TIME_MOCK_H
#define BPF_USPACE_TIME_MOCK_H

#include <stdbool.h>
#include <stdlib.h>

#define ktime_get_ns mock_ktime_get_ns
#include "lib/time.h"

//Automatically increment wall clock on each get
extern bool mock_time_inc;

//Wall clock
extern __u64 mock_time_now;

static __u64 mock_ktime_get_ns(void)
{
	mock_time_now += mock_time_inc ? rand() % 1024ULL : 0ULL;
	return mock_time_now * NSEC_PER_SEC;
}

static inline void mock_time_set_inc(bool inc)
{
	mock_time_inc = inc;
}

static inline void mock_set_time(__u64 value)
{
	mock_time_now = value;
}

#endif //BPF_USPACE_TIME_MOCK_H
