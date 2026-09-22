# In-kernel exact comm exec matching

This case verifies that an authoritative exact `comm` policy is complete before
userspace handles the exec event.

The test stops the p-mark userspace process with `SIGSTOP` while its BPF links
remain attached. It then checks these cases:

- many matching processes create their first socket immediately after exec;
- every first socket already has the configured `SO_MARK`; and
- a marked process execs a non-matching program and its first socket has mark
  zero.

The final case verifies that an authoritative miss clears a same-generation
inherited or previous exec value in the kernel.
