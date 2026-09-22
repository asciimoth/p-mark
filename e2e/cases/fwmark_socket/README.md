# fwmark_socket

Runs `pmark` with its cgroup socket hook and checks `SO_MARK` on real sockets.

Assertions:

- a socket opened before a process matches a rule starts unmarked;
- adding a matching rule reconciles the already-open socket;
- sockets created after the update get the fwmark from the eBPF hook;
- removing the rule clears both existing socket marks.

