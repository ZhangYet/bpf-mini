#include "common.h"
#include "megasas.skel.h"

int main(int argc, char **argv)
{
  struct megasas_bpf *skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  skel = megasas_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = megasas_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  err = megasas_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	 "to see output of the BPF programs.\n");

  for (;;) {
    /* trigger our BPF program */
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  megasas_bpf__destroy(skel);
  return -err;
}
