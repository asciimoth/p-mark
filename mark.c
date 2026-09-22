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

#define KERNEL_POLICY_USERSPACE_ONLY 0
#define KERNEL_POLICY_POSITIVE_ONLY 1
#define KERNEL_POLICY_AUTHORITATIVE 2

#define MAX_KERNEL_COMM_RULES 1024

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
 * Exact comm policies use generation-qualified keys. Userspace populates a
 * complete inactive generation before it changes active_policy. This lets an
 * exec observe either complete policy generation, never a partial update.
 */
struct comm_rule_key {
	__u64 generation;
	char comm[TASK_COMM_LEN];
};

struct comm_rule_value {
	__s8 priority;
	__u64 mark;
};

struct kernel_policy_state {
	__u64 generation;
	__u8 mode;
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct comm_rule_key);
	__type(value, struct comm_rule_value);
	__uint(max_entries, MAX_KERNEL_COMM_RULES * 2);
} comm_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, __u32);
	__type(value, struct kernel_policy_state);
	__uint(max_entries, 1);
} active_policy SEC(".maps");

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

static __always_inline bool next_process_value_wins(const struct process_value *old, const struct process_value *next)
{
	/* Keep this order in sync with preferProcessValue in mark.go. */
	if (old->tombstone != next->tombstone) {
		return next->tombstone;
	}
	if (old->generation != next->generation) {
		return next->generation > old->generation;
	}
	if (old->priority != next->priority) {
		return next->priority > old->priority;
	}
	/* The historical field name is inverted: true means explicit. */
	if (old->inheritance != next->inheritance) {
		return next->inheritance;
	}
	return next->timestamp >= old->timestamp;
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
	struct kernel_policy_state *policy;
	struct comm_rule_value *rule;
	struct comm_rule_key rule_key = {};
	struct process_value candidate = {};
	__u32 policy_key = 0;
	__u32 pid = task->pid;
	__u32 tgid = task->tgid;
	bool has_mark = false;

	if (pid != tgid) {
		return 0;
	}

	existing_value = bpf_map_lookup_elem(&processes, &key);
	if (existing_value) {
		value = *existing_value;
	}

	/*
	 * Apply the exec decision before reserving an event. The process map update
	 * must not depend on ring-buffer space or userspace scheduling.
	 */
	policy = bpf_map_lookup_elem(&active_policy, &policy_key);
	if (policy && policy->generation != 0 &&
	    (policy->mode == KERNEL_POLICY_POSITIVE_ONLY || policy->mode == KERNEL_POLICY_AUTHORITATIVE)) {
		rule_key.generation = policy->generation;
		copy_task_comm(rule_key.comm, task);
		rule = bpf_map_lookup_elem(&comm_rules, &rule_key);

		/* A missing process entry already represents an authoritative miss. */
		if (rule || (policy->mode == KERNEL_POLICY_AUTHORITATIVE && existing_value)) {
			candidate.generation = policy->generation;
			candidate.timestamp = now_ns();
			if (rule) {
				candidate.inheritance = true;
				candidate.has_mark = true;
				candidate.priority = rule->priority;
				candidate.mark = rule->mark;
			} else if (existing_value && existing_value->generation == policy->generation) {
				/*
				 * Preserve comparison fields so a same-generation miss can
				 * clear a prior or inherited mark by its newer timestamp.
				 */
				candidate.inheritance = existing_value->inheritance;
				candidate.priority = existing_value->priority;
				candidate.mark = existing_value->mark;
			}

			if (!existing_value || next_process_value_wins(existing_value, &candidate)) {
				if (bpf_map_update_elem(&processes, &key, &candidate, BPF_ANY) == 0) {
					value = candidate;
				}
			}
		}
	}

	has_mark = !value.tombstone && value.has_mark;

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
