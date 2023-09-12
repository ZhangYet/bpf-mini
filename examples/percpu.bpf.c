#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, u32);
  __type(value, __u64);
  __uint(max_entries, 64);
} map1 SEC(".maps");

inline int counter(blk_status_t error)
{
  u64 *valp, init = 1;
  u32 key = (u32)error;

  valp = bpf_map_lookup_elem(&map1, &key);
  if (!valp) {
    bpf_map_update_elem(&map1, &key, &init, BPF_ANY);
    return 0;
  }

  __sync_fetch_and_add(valp, 1);
  
  return 0;
}

SEC("kprobe/blk_mq_end_request")
int BPF_KPROBE(blk_mq_end_request, struct request * rq, blk_status_t error)
{
  return counter(error);
}

SEC("kprobe/scsi_end_request")
int BPF_KPROBE(probe_scsi_end_request, struct request *req, blk_status_t error,
	       unsigned int bytes)
{
  return counter(error);
}
