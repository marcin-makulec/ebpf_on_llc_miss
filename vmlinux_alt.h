#include "on_llc_miss.bpf.skel.h"

typedef short unsigned int __u16;

typedef __u16 u16;

typedef unsigned char __u8;

typedef __u8 u8;

typedef struct {
  int counter;
} atomic_t;

struct qspinlock {
  union {
    atomic_t val;
    struct {
      u8 locked;
      u8 pending;
    };
    struct {
      u16 locked_pending;
      u16 tail;
    };
  };
};

typedef struct qspinlock arch_spinlock_t;

struct raw_spinlock {
  arch_spinlock_t raw_lock;
};

struct spinlock {
  union {
    struct raw_spinlock rlock;
  };
};

typedef struct spinlock spinlock_t;

struct optimistic_spin_queue {
  atomic_t tail;
};

typedef struct qspinlock arch_spinlock_t;

struct list_head {
  struct list_head *next;
  struct list_head *prev;
};

typedef struct raw_spinlock raw_spinlock_t;

typedef long long int __s64;

typedef __s64 s64;

typedef struct {
  s64 counter;
} atomic64_t;

typedef atomic64_t atomic_long_t;

struct mutex {
  atomic_long_t owner;
  raw_spinlock_t wait_lock;
  struct optimistic_spin_queue osq;
  struct list_head wait_list;
};

typedef long long unsigned int __u64;
typedef __u64 u64;

typedef unsigned int __u32;
typedef __u32 u32;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
  atomic_long_t data;
  struct list_head entry;
  work_func_t func;
};

struct callback_head {
  struct callback_head *next;
  void (*func)(struct callback_head *);
};

struct bpf_map {
  const struct bpf_map_ops *ops;
  struct bpf_map *inner_map_meta;
  void *security;
  enum bpf_map_type map_type;
  u32 key_size;
  u32 value_size;
  u32 max_entries;
  u64 map_extra;
  u32 map_flags;
  u32 id;
  struct btf_record *record;
  int numa_node;
  u32 btf_key_type_id;
  u32 btf_value_type_id;
  u32 btf_vmlinux_value_type_id;
  struct btf *btf;
  struct obj_cgroup *objcg;
  char name[16];
  struct mutex freeze_mutex;
  atomic64_t refcnt;
  atomic64_t usercnt;
  union {
    struct work_struct work;
    struct callback_head rcu;
  };
  atomic64_t writecnt;
  struct {
    const struct btf_type *attach_func_proto;
    spinlock_t lock;
    enum bpf_prog_type type;
    bool jited;
    bool xdp_has_frags;
  } owner;
  bool bypass_spec_v1;
  bool frozen;
  bool free_after_mult_rcu_gp;
  bool free_after_rcu_gp;
  atomic64_t sleepable_refcnt;
  s64 *elem_count;
};