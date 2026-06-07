package pmark

//go:generate go tool bpf2go -cc bpf-clang -tags linux mark mark.c
