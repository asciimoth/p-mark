//go:build ignore

#include <stdbool.h>
#include <asm/param.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef USER_HZ
#define USER_HZ 100ULL
#endif

#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif

#ifndef SO_MARK
#define SO_MARK 36
#endif

#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_USER_TICK (NSEC_PER_SEC / USER_HZ)

struct task_struct {
	int pid;
	int tgid;
	__u64 start_boottime;
	struct task_struct *group_leader;
} __attribute__((preserve_access_index));

struct process_key {
	__u32 tgid;
	__u64 start_time;
};

struct process_value {
	bool tombstone;
	bool inheritance;
	bool has_mark;
	__s8 priority;
	__u64 generation;
	__u64 mark;
	__u64 timestamp;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct process_key);
	__type(value, struct process_value);
	__uint(max_entries, 32768);
} processes SEC(".maps");

static __always_inline struct process_key current_process_key(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	struct task_struct *leader = task->group_leader;
	struct process_key key = {};

	if (!leader) {
		leader = task;
	}

	key.tgid = leader->tgid;
	key.start_time = leader->start_boottime / NSEC_PER_USER_TICK;

	return key;
}

static __always_inline bool current_process_fwmark(__u32 *fwmark)
{
	struct process_key key = current_process_key();
	struct process_value *value;

	value = bpf_map_lookup_elem(&processes, &key);
	if (!value || value->tombstone || !value->has_mark) {
		return false;
	}

	*fwmark = value->mark >> 32;
	return *fwmark != 0;
}

SEC("cgroup/sock_create")
int fwmark_sock_create(struct bpf_sock *ctx)
{
	__u32 fwmark;

	if (current_process_fwmark(&fwmark)) {
		ctx->mark = fwmark;
	}
	return 1;
}

// TODO: Maybe we should use cgroup/connect* and cgroup/sendmsg* too?
//
// SEC("cgroup/connect4")
// int fwmark_connect4(struct bpf_sock_addr *ctx)
// {
// 	return 1;
// }
//
// SEC("cgroup/connect6")
// int fwmark_connect6(struct bpf_sock_addr *ctx)
// {
// 	return 1;
// }
//
// SEC("cgroup/sendmsg4")
// int fwmark_sendmsg4(struct bpf_sock_addr *ctx)
// {
// 	return 1;
// }
//
// SEC("cgroup/sendmsg6")
// int fwmark_sendmsg6(struct bpf_sock_addr *ctx)
// {
// 	return 1;
// }

char __license[] SEC("license") = "Dual MIT/GPL";
