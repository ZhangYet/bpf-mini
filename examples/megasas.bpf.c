#include "vmlinux.h"
#include "megaraid_sas.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
}  megasas_raid_events SEC(".maps");

struct megasas_event {
  __le32 code;
};

SEC("kprobe/megasas_aen_polling")
int BPF_KPROBE(probe_megasas_aen_polling, struct work_struct *work)
{
  struct megasas_event *event = bpf_ringbuf_reserve(&megasas_raid_events,
  						    sizeof(struct megasas_event), 0);
  if (!event)
    return 0;

  struct megasas_aen_event *ev =
    container_of(work, struct megasas_aen_event, hotplug_work.work);

  if (!ev)
    return 0;
  
  struct megasas_instance *instance;
  bpf_core_read(&instance, sizeof(struct megasas_instance*), &ev->instance);
  if (!instance)
    return 0;

  event->code = BPF_CORE_READ(instance, evt_detail, code);
  bpf_ringbuf_submit(event, 0);
  return 0;
}
