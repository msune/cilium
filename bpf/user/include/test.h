/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef BPF_USPACE_TEST_H
#define BPF_USPACE_TEST_H

/**
* Initialize test
*/
#define test_init() int __test_rcs = 0, __test_execs = 0
#define test_init_msg(MSG, ...) test_init(); fprintf(stderr, "[TEST] Starting " MSG, __VA_ARGS__)

/**
* Test assert return code
*/
#define test_assert_rc(NAME, EXP_RC, F) do {			\
	int rc = F;						\
	if ( rc != EXP_RC ) {					\
		fprintf(stderr, "[TEST][%s:%d] FAILED " #NAME ": got '%d', expected '%d'\n", \
						__FILE__,	\
						__LINE__,	\
						rc,		\
						EXP_RC);	\
		++__test_rcs;					\
	}							\
	} while(0); ++__test_execs

/**
* Test condition (external counter)
*/
#define test_assert_ext(NAME, EXP, ERR_CNT, EXEC_CNT)			\
	if ( ! ( EXP ) ) {						\
		fprintf(stderr, "[TEST][%s:%d] FAILED "#NAME": '" #EXP "'\n",\
						__FILE__, __LINE__);	\
		++ERR_CNT;						\
	}								\
	++EXEC_CNT

/**
* Test condition
*/
#define test_assert(NAME, EXP) \
	test_assert_ext(NAME, EXP, __test_rcs, __test_execs)

/**
* Collect results of all asserts
*/
#define test_result() (__test_rcs)
#define test_result_msg(MSG, ...) \
	fprintf(stderr, "[TEST] %s asserts %d/%d " MSG, \
					__test_rcs? "FAILED" : "PASSED", \
					__test_rcs, __test_execs, \
					__VA_ARGS__)

#endif //BPF_USPACE_TEST_H
