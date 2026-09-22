package pmark

//go:generate go tool bpf2go -cc bpf-clang -tags linux mark mark.c -- -Wall -Wextra -Werror -Wno-unused-parameter -Wformat=2 -Wshadow -Wundef
