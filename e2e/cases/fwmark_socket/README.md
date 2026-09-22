# fwmark_socket

Runs `pmark` with its cgroup socket hooks and checks `SO_MARK` on real sockets.

Assertions:

- a socket opened before a process matches a rule starts unmarked;
- adding a matching rule reconciles the already-open socket;
- sockets created after the update get the fwmark from the eBPF hook;
- clearing `SO_MARK` before IPv4 `connect()` repairs the mark 100 times;
- clearing `SO_MARK` before IPv6 `connect()` repairs the mark 100 times when
  IPv6 loopback is available;
- removing the rule clears both existing socket marks;
- an unmarked process can connect and keeps mark zero; and
- a process mark that derives fwmark zero does not change or reject a marked
  socket during `connect()`.
