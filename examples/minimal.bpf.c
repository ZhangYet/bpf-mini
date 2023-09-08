// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>
#include <bpf_core_read.h>
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

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
int my_pid = 0;

char fmt[] = "dante debug: %s";
char f_fmt[] = "file path: %s";

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_probe, struct file *f, const char *buf, size_t count, loff_t *pos)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  if (pid != my_pid)
	return 0;

  const unsigned char* name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
  if (!name) {
        bpf_trace_printk(fmt, sizeof(fmt), "no name");
        return 0;
  }
  bpf_trace_printk(f_fmt, sizeof(f_fmt), name);
  return 0;
}
