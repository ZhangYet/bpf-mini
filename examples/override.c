#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "override.skel.h"
#include <errno.h>
#include <signal.h>

#define WARN(...) fprintf(stderr, __VA_ARGS__)

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
  struct override_bpf *skel;
  int err;

  libbpf_set_print(libbpf_print_fn);
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  skel = override_bpf__open();
  if (!skel) {
    WARN("open failed\n");
    return 1;
  }

  err = override_bpf__load(skel);
  if (err) {
    WARN("load failed: %d\n", err);
    return err;
  }

  err = override_bpf__attach(skel);
  if (err) {
    WARN("attach failed: %d\n", err);
    return err;
  }

  while(!exiting)
    ;

  return 0;
}
