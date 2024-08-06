/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

enum cilium_feature {
	CILIUM_FEAT_ENABLE_CAPTURE = 1
};

#define CILIUM_FEATURES_MAGIC_ID 0xCAFE

static __always_inline bool cilium_feature_enabled(enum cilium_feature)
{
	__u32 key = CILIUM_FEATURES_MAGIC_ID;
	uint64_t* bitmap = map_lookup_elem(&ENDPOINTS_MAP, &key);

	if (!bitmap) {
		//XXX this should be fatal
		return false;
	}

	return *bitmap&cilium_feature > 0;
}
