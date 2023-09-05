#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include "percpu.skel.h"
#include "percpu.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
  exiting = true;
}

int main(int argc, char** argv)
{
  struct percpu_bpf *skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);  

  skel = percpu_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }
  fprintf(stderr, "Succ to open BPF skeleton\n");

  err = percpu_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeletion\n");
    return 1;
  }
  fprintf(stderr, "Succ to load and verify BPF skeletion\n");

  err = percpu_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }
  fprintf(stderr, "Succ to attach BPF skeleton\n");

  int fd = bpf_map__fd(skel->maps.map1);
  u32 *key = NULL, *next_key = NULL;
  u64 value;
  
  while(!exiting) {
    err = bpf_map_get_next_key(fd, key, next_key);
    if (err) {
      if (errno == ENOENT) {
	err = 0;
	fprintf(stderr, "errno == ENOENT\n");
	continue;
      }
      fprintf(stderr, "bpf_map_get_next_key failed: %s\n", strerror(errno));
      return err;
    }

    err = bpf_map_lookup_elem(fd, next_key, &value);
    if (err) {
      fprintf(stderr, "bpf_map_lookup_elem failed: %s\n", strerror(errno));
      return err;
    }
    fprintf(stdout, "%d:\t%lld\n", *next_key, value);
    key = next_key;
    sleep(3);
  }

cleanup:
  percpu_bpf__destroy(skel);
  
  return 0;
}
  
