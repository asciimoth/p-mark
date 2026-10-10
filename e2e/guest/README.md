# Disposable guest end-to-end tests

The guest runner builds `pmark` and the probes from the current source tree.
It then boots them in a disposable Linux VM. The VM has no network device and
no host filesystem mount. Tests use only the guest loopback device.

Run all focused marking cases:

```sh
just test-e2e-guest
```

Run one or more selected cases:

```sh
just test-e2e-guest kernel_comm_exec fwmark_socket
```

The command supports x86-64 hosts. It requires Docker, QEMU
`qemu-system-x86_64`, `timeout`, and at least 2 GiB of available memory. It
uses KVM when `/dev/kvm` is usable. Otherwise, it uses the QEMU TCG emulator.
TCG is slower, especially for `tombstone_churn`.

The process that starts QEMU does not need root access. The test processes run
as root in the VM. They need BPF, perf-event, network-admin, and system-admin
capabilities in that VM. The supplied Debian kernel configuration provides:

- BPF system calls and the BPF JIT;
- BPF tracepoints for process fork, exec, and exit;
- cgroup v2 with BPF `sock_create`, `connect4`, and `connect6` attachment;
- bpffs, procfs, IPv4, IPv6, TCP, and UDP; and
- `SO_MARK` support.

The runner saves the exact kernel version and configuration with each result.
It also records the source revision, VM launch settings, serial log, case
results, policy mode, and rule generation under `e2e/artifacts/guest/`.
Launch credentials and effective capabilities are in the serial log.

Each case has a 180-second limit. The complete VM has a 600-second limit. Set
`E2E_GUEST_CASE_TIMEOUT` or `E2E_GUEST_TIMEOUT` to change these limits. Other
settings are `E2E_GUEST_MEMORY`, `E2E_GUEST_CPUS`,
`E2E_GUEST_ARTIFACT_DIR`, and `E2E_GUEST_REBUILD=1`.

The VM mounts its own procfs, cgroup v2, and bpffs. BusyBox `init` runs as PID
1 and reaps child processes. The cases run in the VM's initial PID namespace,
so tracepoint TGIDs match guest `/proc` entries. After each case, the runner
checks for remaining `pmark` processes, test pin directories, and BPF links.

The Dockerfile is only an image builder. Its explicit build step creates a
kernel and an initramfs under `/guest-artifacts`; it does not run a test or
load a BPF program. The host runner extracts these files and starts QEMU. A
container created from the image runs `/bin/true`.

The host accepts a run only when QEMU exits normally, every selected case has
one passing result, and the guest prints its final passing result. A timeout,
kernel panic, incomplete serial log, failed assertion, or abnormal shutdown
causes a nonzero exit status.
