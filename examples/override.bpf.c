#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/should_fail_bio")
int override_queue_rq(struct pt_regs *ctx)
{
  unsigned long rc = 5;
  bpf_override_return(ctx, rc);
  return 0;
}

