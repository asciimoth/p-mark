// Package fwmark applies pmark process marks to Linux socket fwmarks.
//
// The package is an example consumer of the root package's pinned processes map.
// Its eBPF cgroup/sock_create, connect4, and connect6 programs look up the
// current process lifetime and copy the high 32 bits of the 64-bit pmark value
// into the socket mark. The connect programs repeat the operation before route
// selection and reject the connection if a required mark cannot be applied.
// The Go Manager also reconciles already-open sockets through pidfd_getfd and
// SO_MARK when pmark emits ProcessUpdate callbacks.
//
// Use ToMark and FromMark to convert between a 32-bit Linux fwmark and the
// 64-bit mark value understood by package pmark.
package fwmark
