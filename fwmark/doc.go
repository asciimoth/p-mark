// Package fwmark applies pmark process marks to Linux socket fwmarks.
//
// The package is an example consumer of the root package's pinned processes map.
// Its eBPF cgroup/sock_create program looks up the current process lifetime and
// copies the high 32 bits of the 64-bit pmark value into bpf_sock.mark. The Go
// Manager also reconciles already-open sockets through pidfd_getfd and
// SO_MARK when pmark emits ProcessUpdate callbacks.
//
// Use ToMark and FromMark to convert between a 32-bit Linux fwmark and the
// 64-bit mark value understood by package pmark.
package fwmark
