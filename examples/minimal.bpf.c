// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
/*
int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
*/

SEC("tp/irq/softirq_entry")
int handle_tp(struct trace_event_raw_softirq *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("softirq triggered from PID: %d, vec: %d\n", pid, ctx->vec);
}
