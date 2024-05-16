#ifndef BPF_USPACE_BUILTIN_MOCK_H
#define BPF_USPACE_BUILTIN_MOCK_H

//Sanity
#ifdef __BPF_BUILTINS__
	#error user_builtins.h must be included before any other header!
#endif //__BPF_BUILTINS__

//Do not include BPF custom builtins
#define __BPF_BUILTINS__ 1

#include <string.h>

//Other
#define __align_stack_8

#define __bpf_memcpy_builtin memcpy

#endif //BPF_USPACE_BUILTIN_MOCK_H
