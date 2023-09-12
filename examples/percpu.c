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

static void print_map(int fd)
{
  u32 *key = NULL, next_key;
  u64 value[2];
  int err;
  
  while(1) {
    err = bpf_map_get_next_key(fd, key, &next_key);
    if (err) {
      if (errno == ENOENT)
	return;
      fprintf(stderr, "bpf_map_get_next_key failed: %s\n", strerror(errno));
      return;
    }
    
    err = bpf_map_lookup_elem(fd, &next_key, &value);
    if (err) {
      fprintf(stderr, "bpf_map_lookup_elem failed: %s\n", strerror(errno));
      return;
    }
    key = &next_key;
  
    fprintf(stdout, "%d:\t%lld\t%lld\n", next_key, value[0], value[1]);
  }
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
  
  while(!exiting) {
    print_map(fd);
    fprintf(stdout, "sleep\n");
    sleep(3);
  }

cleanup:
  percpu_bpf__destroy(skel);
  
  return 0;
}
  
