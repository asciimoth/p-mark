package fwmark

//go:generate go tool bpf2go -cc bpf-clang -tags linux fwmark fwmark.c
