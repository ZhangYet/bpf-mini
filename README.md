#bpf-mini

bpf-mini is a project I used to featured how to compile an ebpf project.
The community give the [libbpf-boostrap](https://github.com/libbpf/libbpf-bootstrap) as example.
I think its Makefile is too complicated. So I copy the minimal example and build the bpf-mini

The Makefile does a lot of thing in libbpf-boostrap project. In this simplified version, it builds 
the libbpf and the bpftool at fist. The core part is as below:

```bash
clang-10 -g -O2 -target bpf -D__TARGET_ARCH_x86               \
             -I.output -I../libbpf/include/uapi -I../vmlinux/x86/ -idirafter /usr/local/include -idirafter /usr/lib/llvm-10/lib/clang/10.0.0/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include                 \
             -c minimal.bpf.c -o .output/minimal.tmp.bpf.o
.output/bpftool/bootstrap/bpftool gen object .output/minimal.bpf.o .output/minimal.tmp.bpf.o
.output/bpftool/bootstrap/bpftool gen skeleton .output/minimal.bpf.o > .output/minimal.skel.h
cc -g -Wall -I.output -I../libbpf/include/uapi -I../vmlinux/x86/ -c minimal.c -o .output/minimal.o
cc -g -Wall .output/minimal.o /home/vagrant/repo/bpf-mini/examples/.output/libbpf.a   -lrt -ldl -lpthread -lm -lelf -lz -o minimal
```
1. Generate a BPF ELF object(minimal.tmp.bpf.o) from minimal.bpf.c.
2. Generate a BPF ELF object(minimal.bpf.o) by `bpftool gen object` .
3. Generate a BPF skeleton C header file(minimal.skel.h) from minimal.bpf.o by `bpftool gent skeleton`. 
4. Compile minimal.c with minimal.skel.h.
5. Link all to generate the binary file.

