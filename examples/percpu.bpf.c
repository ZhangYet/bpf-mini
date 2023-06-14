#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, blk_status_t);
  __uint(max_entries, 32);
} map1 __section(".maps");

SEC("kprobe/blk_mq_end_request")
int BPF_KPROBE(blk_mq_end_request, struct request * rq, blk_status_t error)
{
  u64 *valp, init = 1;

  valp = bpf_map_lookup_elem(&map1, &error);
  if (!valp) {
    bpf_map_update_elem(&map1, &error, &init, BPF_ANY);
    return 0;
  }

  __sync_fetch_and_add(valp, 1);
  
  return 0;
}
