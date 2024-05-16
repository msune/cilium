#ifndef BPF_USPACE_HELPERS_MOCK_H
#define BPF_USPACE_HELPERS_MOCK_H

//Sanity
#ifdef __BPF_HELPERS__
	#error user_helpers.h must be included before any other header!
#endif //__BPF_HELPERS__

#define ctx_load_bytes mock_skb_load_bytes
#define ctx_store_bytes mock_skb_store_bytes

/**
* NOTE: this file should ONLY be used when something needs to be defined
* before the helpers are included. For the rest use mocks.
*/

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

//fwd decl
struct __sk_buff;
typedef __u32 u32;
typedef __u64 u64;

static inline long mock_skb_load_bytes(const void *skb, u32 offset,
					void *to, u32 len)
{
	__u8* aux = (void*)skb;
	memcpy(aux, to, len);
	return 0;
}

static inline long mock_skb_store_bytes(struct __sk_buff *skb, u32 offset,
					const void *from, u32 len, u64 flags)
{
	__u8* aux = (void*)skb;
	memcpy(aux+offset, from, len);
	return 0;
}

#endif //BPF_USPACE_HELPERS_MOCK_H
