# Docker E2E Tests

The `e2e/` suite builds the real `pmark` command and runs it in Docker. The
cases exercise Linux eBPF tracepoints, bpffs maps, the control API, process-mark
inheritance, and cgroup socket marks.

Run all cases:

```sh
just test-e2e
```

Run selected cases:

```sh
./e2e/run.sh daemon_lifecycle fwmark_socket
```

The containers use `--privileged` and the host PID namespace. The host PID
namespace is required because process tracepoints report host TGIDs, and p-mark
must read the same identities from `/proc`. Each case uses a separate bpffs pin
directory and removes it on exit. Run this suite only on a disposable test host
that permits privileged Docker containers.

The runner uses one case at a time by default. Set `E2E_JOBS` to run more cases
in parallel. Each case's output stays grouped, and the runner reports all case
failures after the active cases finish.

The runner labels the Docker image with a hash of its source inputs. Later runs
reuse an unchanged image without contacting an image registry. Set
`E2E_REBUILD=1` to force a build. Failed image builds use bounded exponential
backoff; `E2E_BUILD_ATTEMPTS`, `E2E_BUILD_RETRY_DELAY`, and
`E2E_BUILD_RETRY_MAX_DELAY` control it.

Enable Go coverage for the instrumented `pmark` process with:

```sh
E2E_COVERAGE=1 ./e2e/run.sh
```

The coverage profiles and reports are written to `e2e/coverage/`. Set
`E2E_COVERAGE_DIR` or `E2E_COVERPKG` to change the output path or package set.

## Layout

Each case lives in `e2e/cases/<case-name>/` and contains:

- `README.md`: expected behavior and assertions.
- `setup.sh`: optional setup that runs inside the container.
- `test.sh`: executable test logic. It sources `/e2e/lib/common.sh` and uses
  `start_daemon`, `state`, `retry`, and `stop_daemon`.

The harness copies each case to an isolated directory under `/tmp` before it
runs the case. The case can write temporary files in `$E2E_RUNTIME` without
changing the source tree.

