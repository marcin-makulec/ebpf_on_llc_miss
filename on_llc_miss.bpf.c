#include "on_llc_miss.h"
#include "vmlinux_full.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define MAX_STACK_DEPTH 10

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(max_entries, 4096);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u64) * MAX_STACK_DEPTH);
} stacks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("perf_event")
int on_cache_miss(void *ctx) {
  struct event payload = {};

  payload.stack_id =
      bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);

  if (!payload.stack_id) {
    return 1;
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload,
                        sizeof(payload));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";