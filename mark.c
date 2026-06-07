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

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/*
 * procfs exposes task start time in USER_HZ clock ticks. Keeping the same unit
 * in the BPF event lets Go build identical keys from /proc/<pid>/stat before
 * the BPF programs are attached.
 *
 * This is timekeeping state, not a CPU cycle counter, so CPU frequency changes,
 * CONFIG_HZ, and tickless scheduling do not change the scale. The kernel procfs
 * implementation prints /proc/<pid>/stat field 22 from task->start_boottime via
 * nsec_to_clock_t(timens_add_boottime_ns(...)). USER_HZ is the userspace ABI
 * clock tick rate returned by sysconf(_SC_CLK_TCK), normally 100 on Linux.
 *
 * The one important caveat is time namespaces: procfs applies the namespace
 * boottime offset, while this BPF program reads the raw task_struct field. Keep
 * userspace in the same time namespace as the observed host, or account for the
 * namespace offset before comparing keys.
 */
#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_USER_TICK (NSEC_PER_SEC / USER_HZ)

#define EVENT_FORK 1
#define EVENT_EXIT 2
#define EVENT_EXEC 3

/*
 * Small CO-RE view of task_struct. start_boottime is the timestamp used by
 * procfs for field 22 in /proc/<pid>/stat, so it can be shared with userspace.
 */
struct task_struct {
	int pid;
	int tgid;
	__u64 start_boottime;
	char comm[TASK_COMM_LEN];
} __attribute__((preserve_access_index));

/*
 * A PID can be reused, so TGID alone is not a process identity. Pair TGID with
 * procfs-compatible start time ticks to identify one process lifetime per boot.
 * The tick granularity is usually 10ms, which is enough to distinguish normal
 * PID reuse but not a cryptographic process UUID.
 */
struct process_key {
	__u32 tgid;
	__u64 start_time;
};

/*
 * Map entries represent effective marks plus checker provenance. A missing
 * entry, a live entry with has_mark=false, and a tombstone all mean "unmarked"
 * for policy. Live no-mark entries are kept after a process had a mark once so
 * newer checker generations can remove a mark without losing lifetime state.
 * Only userspace tombstone collection physically deletes entries.
 */
struct process_value {
	bool tombstone;
	bool inheritance;
	bool has_mark;
	__s8 priority;
	__u64 generation;
	__u64 mark;
	__u64 timestamp;
};

/*
 * Ring events carry the kernel's view at the time of the transition.
 */
struct event {
	__u32 type;
	struct process_key key;
	struct process_key parent_key;
	__u32 pid;
	__u32 ppid;
	bool has_mark;
	struct process_value value;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct process_key);
	__type(value, struct process_value);
	__uint(max_entries, 32768);
} processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

static __always_inline __u64 now_ns(void)
{
	return bpf_ktime_get_boot_ns();
}

static __always_inline struct process_key process_key_from_task(struct task_struct *task)
{
	struct process_key key = {};

	key.tgid = task->tgid;
	key.start_time = task->start_boottime / NSEC_PER_USER_TICK;

	return key;
}

static __always_inline void copy_task_comm(char *dst, struct task_struct *task)
{
	__builtin_memcpy(dst, task->comm, TASK_COMM_LEN);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_sched_process_fork, struct task_struct *parent, struct task_struct *child)
{
	struct process_key key = process_key_from_task(child);
	struct process_key parent_key = process_key_from_task(parent);
	struct process_value value = {};
	struct process_value *parent_value;
	struct process_value *existing_value;
	__u32 child_pid = child->pid;
	__u32 child_tgid = child->tgid;
	bool has_mark = false;

	if (child_pid != child_tgid) {
		return 0;
	}

	/*
	 * Inheritance is resolved before the fork event is submitted. If another
	 * BPF program or userspace inserted the child first, report only a live
	 * value with has_mark=true as a mark. Live no-mark entries deliberately do
	 * not inherit and do not make the event marked.
	 */
	existing_value = bpf_map_lookup_elem(&processes, &key);
	if (existing_value) {
		value = *existing_value;
		has_mark = !existing_value->tombstone && existing_value->has_mark;
	} else {
		parent_value = bpf_map_lookup_elem(&processes, &parent_key);
		if (parent_value && !parent_value->tombstone && parent_value->has_mark) {
			value = *parent_value;
			value.tombstone = false;
			value.inheritance = false;
			value.timestamp = now_ns();
			if (bpf_map_update_elem(&processes, &key, &value, BPF_NOEXIST) == 0) {
				has_mark = true;
			} else {
				existing_value = bpf_map_lookup_elem(&processes, &key);
				if (existing_value) {
					value = *existing_value;
					has_mark = !existing_value->tombstone && existing_value->has_mark;
				}
			}
		}
	}

	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->type = EVENT_FORK;
	event->key = key;
	event->parent_key = parent_key;
	event->pid = child_pid;
	event->ppid = parent->tgid;
	event->has_mark = has_mark;
	event->value = value;
	copy_task_comm(event->comm, child);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_sched_process_exit, struct task_struct *task)
{
	struct process_key key = process_key_from_task(task);
	struct process_value value = {};
	struct process_value *existing_value;
	__u32 pid = task->pid;
	__u32 tgid = task->tgid;
	bool has_mark = false;

	if (pid != tgid) {
		return 0;
	}

	/*
	 * Stop transitions tombstone any existing mark instead of deleting it.
	 * Userspace removes old tombstones from both mirrors after a grace period.
	 */
	existing_value = bpf_map_lookup_elem(&processes, &key);
	if (existing_value) {
		value = *existing_value;
		value.tombstone = true;
		value.timestamp = now_ns();
		bpf_map_update_elem(&processes, &key, &value, BPF_ANY);
		has_mark = !existing_value->tombstone && existing_value->has_mark;
	}

	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->type = EVENT_EXIT;
	event->key = key;
	event->parent_key = (struct process_key){};
	event->pid = pid;
	event->ppid = 0;
	event->has_mark = has_mark;
	event->value = value;
	copy_task_comm(event->comm, task);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_sched_process_exec, struct task_struct *task, int old_pid, void *bprm)
{
	struct process_key key = process_key_from_task(task);
	struct process_value value = {};
	struct process_value *existing_value;
	__u32 pid = task->pid;
	__u32 tgid = task->tgid;
	bool has_mark = false;

	if (pid != tgid) {
		return 0;
	}

	existing_value = bpf_map_lookup_elem(&processes, &key);
	if (existing_value) {
		value = *existing_value;
		has_mark = !existing_value->tombstone && existing_value->has_mark;
	}

	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	event->type = EVENT_EXEC;
	event->key = key;
	event->parent_key = (struct process_key){};
	event->pid = pid;
	event->ppid = 0;
	event->has_mark = has_mark;
	event->value = value;
	copy_task_comm(event->comm, task);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
