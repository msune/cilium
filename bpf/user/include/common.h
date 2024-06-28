/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef EBPF_MOCKS_H
#define EBPF_MOCKS_H

#include <stdlib.h>

//Node CPUs reasonable default
#ifndef __NR_CPUS__
	#define __NR_CPUS__ 4
#endif //__NR_CPUS__

//Make sure this is defined BEFORE any inclusion
#define DEBUG 1

//Some helpers need to be overriden too
#include "user_helpers.h"
//We don't want BPF custom builtins in userspace
#include "user_builtins.h"
#include "user_static_data.h"

#ifdef MOCK_TC
#include <bpf/ctx/skb.h>
#endif //MOCK_TC

//Node stuff
#include "../node_config.h"

//Mocks
#include "signal.h"
#include "log.h"
#include "time.h"
#include "map.h"
#include "rand.h"

#include "test.h"

//Mocks (maps, etc.)
static inline void mock_init()
{
	mock_maps_init();
}
static inline void mock_fini()
{
	mock_maps_fini();
}

#endif //EBPF_MOCKS_H
