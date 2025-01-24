Compile eBPF program:
```
clang -target bpf -g -O2 -c on_llc_miss.bpf.c -o on_llc_miss.bpf.o
```
Generate eBPF skeleton:
```
sudo bpftool gen skeleton on_llc_miss.bpf.o > on_llc_miss.bpf.skel.h
```
Compile userspace program:
```
clang on_llc_miss.c -o loader -lbpf
```
Usage
```
sudo ./loader <pid>
```
