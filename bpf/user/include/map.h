/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef BPF_USPACE_MAP_MOCK_H
#define BPF_USPACE_MAP_MOCK_H

#include <linux/types.h>
#include <linux/bpf.h>

//C++ stuff
#include "utils.h"

//Map interceptors

BEGIN_DECLS //C++

/**
* Intercept map_update_elem
*/
int mock_map_update_elem(const void *map, const void *key, const void *value, __u32 flags);
void* mock_map_lookup_elem(const void *map, const void *key);
int mock_map_delete_elem(void *map, const void *key);
__u32 mock_map_get_size(void* map);
int mock_map_clear(void* map);

#define map_lookup_elem mock_map_lookup_elem
#define map_update_elem mock_map_update_elem
#define map_delete_elem mock_map_delete_elem

//Mocks
void mock_maps_init();
void mock_maps_fini();

END_DECLS //C++

//Define this, as we can't include some BPF code in C++
#define CT_X4_KEY_SIZE 14
#define CT_X6_KEY_SIZE 38
#define CT_XX_VAL_SIZE 56

//Load maps
#ifndef __DONT_INCLUDE_MAPS__
	#include <lib/conntrack_map.h>
	COMPILATION_ASSERT(CT_X4_KEY_SIZE_CHECK,
				sizeof(struct ipv4_ct_tuple) == CT_X4_KEY_SIZE);
	COMPILATION_ASSERT(CT_X6_KEY_SIZE_CHECK,
				sizeof(struct ipv6_ct_tuple) == CT_X6_KEY_SIZE);
	COMPILATION_ASSERT(CT_XX_VAL_SIZE_CHECK,
				sizeof(struct ct_entry) == CT_XX_VAL_SIZE);
#else
	//For C++ (mind should be the unnamed struct)
	extern int test_cilium_ct_tcp4_65535;
	#define CT_MAP_TCP4 test_cilium_ct_tcp4_65535
	extern int test_cilium_ct_tcp6_65535;
	#define CT_MAP_TCP6 test_cilium_ct_tcp6_65535
	extern int test_cilium_ct_any4_65535;
	#define CT_MAP_ANY4 test_cilium_ct_any4_65535
	extern int test_cilium_ct_any6_65535;
	#define CT_MAP_ANY6 test_cilium_ct_any6_65535
#endif

#endif //BPF_USPACE_MAP_MOCK_H
