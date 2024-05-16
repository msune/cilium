/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright Authors of the Linux kernel */
#ifndef BPF_USPACE_SIGNAL_H
#define BPF_USPACE_SIGNAL_H

#include <stdio.h>
#include <linux/bpf.h>

#ifndef __DONT_INCLUDE_SIGNAL__
#include <lib/signal.h>
#endif //__DONT_INCLUDE_SIGNAL__

#define send_signal_nat_fill_up mock_send_signal_nat_fill_up
#define send_signal_ct_fill_up mock_send_signal_ct_fill_up
#define send_signal_auth_required mock_send_signal_auth_required

typedef enum {
	MOCK_CTX_EVENT_TYPE_NAT_FILL_UP,
	MOCK_CTX_EVENT_TYPE_CT_FILL_UP,
	MOCK_CTX_EVENT_TYPE_AUTH_REQUIRED
} mock_ctx_event_type_t;

//fwd decl
struct auth_key;
struct __ctx_buff;

//Callback prototype
typedef void (*mock_ctx_event_output_t)(mock_ctx_event_type_t type, struct __ctx_buff*,
							__u32 proto,
							const struct auth_key*);

extern mock_ctx_event_output_t mock_signal_cb;

static inline void mock_set_capture_signal_cb(mock_ctx_event_output_t hook)
{
	mock_signal_cb = hook;
}

//Mock routines
static void mock_send_signal_nat_fill_up(struct __ctx_buff *ctx,
						    __u32 proto)
{
	if (mock_signal_cb)
		(*mock_signal_cb)(MOCK_CTX_EVENT_TYPE_NAT_FILL_UP, ctx, proto, NULL);
	fprintf(stderr, "[EVENT: NAT_FILL_UP] proto: %d\n", proto);
}

static void mock_send_signal_ct_fill_up(struct __ctx_buff *ctx,
						   __u32 proto)
{
	if (mock_signal_cb)
		(*mock_signal_cb)(MOCK_CTX_EVENT_TYPE_CT_FILL_UP, ctx, proto, NULL);
	fprintf(stderr, "[EVENT: NAT_CT_FILL_UP] proto: %d\n", proto);
}

static void mock_send_signal_auth_required(struct __ctx_buff *ctx,
						      const struct auth_key *auth)
{
	if (mock_signal_cb)
		(*mock_signal_cb)(MOCK_CTX_EVENT_TYPE_CT_FILL_UP, ctx, 0, auth);
	fprintf(stderr, "[EVENT: AUTH_REQ] %p\n", auth);
}

#endif //BPF_USPACE_SIGNAL_H
