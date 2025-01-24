#include "on_llc_miss.h"
#include "vmlinux_alt.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_STACK_DEPTH 10

static volatile int exiting = 0;
static volatile int stacks_map_fd;

void handle_exit(int sig) { exiting = 1; }

void process_event(void *ctx, int cpu, void *data, __u32 size) {
  struct event *event_data = data;
  u64 offsets[MAX_STACK_DEPTH] = {};
  bpf_map_lookup_elem(stacks_map_fd, &event_data->stack_id, offsets);

  printf("LLC miss! Stack:\n");
  for (int i = 0; offsets[i] != 0 && i < MAX_STACK_DEPTH; i++) {
    printf("%p\n", (void *)offsets[i]);
  }
  printf("\n\n");
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
    return 1;
  }

  int target_pid = atoi(argv[1]);
  if (target_pid <= 0) {
    fprintf(stderr, "<pid> must be a positive integer\n");
    return 2;
  }

  struct on_llc_miss_bpf *on_llc_miss = on_llc_miss_bpf__open_and_load();
  if (!on_llc_miss) {
    fprintf(stderr, "Failed to load eBPF program\n");
    return 3;
  }

  int prog_fd = bpf_program__fd(on_llc_miss->progs.on_cache_miss);
  int event_map_fd = bpf_map__fd(on_llc_miss->maps.events);
  stacks_map_fd = bpf_map__fd(on_llc_miss->maps.stacks);

  struct perf_event_attr attr = {
      .type = PERF_TYPE_HARDWARE,
      .config = PERF_COUNT_HW_CACHE_MISSES,
      .sample_period = 1,
      .sample_type = 0,
      .disabled = 1,
  };

  long perf_event_fd = syscall(SYS_perf_event_open, &attr, target_pid, -1, -1,
                               PERF_FLAG_FD_CLOEXEC);

  if (perf_event_fd == -1) {
    fprintf(stderr, "Failed to set up perf event\n");
    on_llc_miss_bpf__destroy(on_llc_miss);
    return 4;
  }

  if (ioctl(perf_event_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) == -1 ||
      ioctl(perf_event_fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
    fprintf(stderr, "Failed to attach eBPF program to perf event\n");
    on_llc_miss_bpf__destroy(on_llc_miss);
    return 5;
  }

  signal(SIGINT, handle_exit);
  signal(SIGTERM, handle_exit);

  struct perf_buffer *pb =
      perf_buffer__new(event_map_fd, 8, process_event, NULL, NULL, NULL);
  if (!pb) {
    fprintf(stderr, "Failed to create perf buffer\n");
    on_llc_miss_bpf__destroy(on_llc_miss);
    return 7;
  }

  printf("Monitoring...\n");
  while (!exiting) {
    perf_buffer__poll(pb, 2000);
  }

  on_llc_miss_bpf__destroy(on_llc_miss);
  return 0;
}
