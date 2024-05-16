#ifndef BPF_USPACE_RAND_MOCK_H
#define BPF_USPACE_RAND_MOCK_H

#define get_prandom_u32 mock_get_prandom_u32

#include <stdlib.h>

static inline __u32 mock_get_prandom_u32()
{
	return rand();
}

#endif //BPF_USPACE_RAND_MOCK_H
