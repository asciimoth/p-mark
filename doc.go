// Package pmark tags Linux process lifetimes with 64-bit marks selected by
// userspace Go callbacks and inherited by children through eBPF.
//
// A Daemon loads tracepoint eBPF programs, pins the shared processes map under
// a bpffs directory, traverses /proc, and keeps a userspace mirror reconciled
// with fork, exec, and exit events. Callers provide a CheckFunc to choose
// explicit marks from ProcessInfo and optional callbacks to observe process
// events or effective map updates.
//
// Process identity is ProcessKey: TGID plus the process start time in procfs
// USER_HZ ticks. ProcessValue stores whether the process is live or a
// tombstone, whether it has an effective mark, mark priority, checker
// generation, mark value, and a CLOCK_BOOTTIME timestamp. Other eBPF programs
// can reuse the pinned processes map as a kernel-space communication point, but
// should treat missing entries, tombstones, and entries with HasMark false as
// unmarked.
package pmark
