#include <bpf_core_read.h>
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

char fmt[] = "[iolatency] %s: %lu";

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(blk_trace, struct request *req, u64 now)
{
  if (now < 0)
    now = bpf_ktime_get_ns();

  u64 alloc_time_ns;
  bpf_core_read(&alloc_time_ns, sizeof(alloc_time_ns), &req->alloc_time_ns);
  bpf_trace_printk(fmt, sizeof(fmt), "alloc_time_ns", alloc_time_ns);
  u64 start_time_ns;
  bpf_core_read(&start_time_ns, sizeof(start_time_ns), &req->start_time_ns);
  bpf_trace_printk(fmt, sizeof(fmt), "start_time_ns", start_time_ns);
  u64 io_start_time_ns;
  bpf_core_read(&io_start_time_ns, sizeof(io_start_time_ns), &req->io_start_time_ns);
  bpf_trace_printk(fmt, sizeof(fmt), "io_start_time_ns", io_start_time_ns);

  if (start_time_ns > 0 && alloc_time_ns > 0)
    bpf_trace_printk(fmt, sizeof(fmt), "congestion_time",
		     start_time_ns - alloc_time_ns);

  if (start_time_ns > 0 && io_start_time_ns > 0)
    bpf_trace_printk(fmt, sizeof(fmt), "wait_time",
		     io_start_time_ns - start_time_ns);

  if (io_start_time_ns > 0)
    bpf_trace_printk(fmt, sizeof(fmt), "process_time",
		     now - io_start_time_ns);

  return 0;
}
