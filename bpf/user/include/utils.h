/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef BPF_USPACE_UTILS_H
#define BPF_USPACE_UTILS_H

#ifdef __cplusplus
	# define BEGIN_DECLS extern "C" {
	# define END_DECLS   }
#else
	# define BEGIN_DECLS
	# define END_DECLS
#endif //__cplusplus

//Compilation assert
#define COMPILATION_ASSERT(TAG, COND) \
	enum { COMPILATION_ASSERT__ ## TAG = 1/(COND) }

#endif //BPF_USPACE_UTILS_H
