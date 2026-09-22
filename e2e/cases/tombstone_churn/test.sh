#!/usr/bin/env bash
set -euo pipefail

source /e2e/lib/common.sh

target_pid=""

cleanup() {
	if [[ -n "$target_pid" ]]; then
		kill "$target_pid" 2>/dev/null || true
		wait "$target_pid" 2>/dev/null || true
	fi
	stop_daemon
}
trap cleanup EXIT

generate_unknown_exits() {
	local count="$1"
	python3 - "$count" <<'PY'
import os
import sys

remaining = int(sys.argv[1])
batch_size = 128
while remaining:
    children = []
    for _ in range(min(batch_size, remaining)):
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        children.append(pid)
    for pid in children:
        os.waitpid(pid, 0)
    remaining -= len(children)
PY
}

probe_socket_mark() {
	E2E_EXPECTED_FWMARK=0x414c4d01 e2e-churn - <<'PY'
import os
import socket
import time

expected = int(os.environ["E2E_EXPECTED_FWMARK"], 0)
deadline = time.monotonic() + 20
observed = 0
while time.monotonic() <= deadline:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        observed = probe.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
    if observed == expected:
        raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"socket mark was {observed:#010x}; expected {expected:#010x}")
PY
}

start_daemon \
	-fwmark \
	-fmark-value 0x414c4d01 \
	-rule-comm '^e2e-churn$'

log "generating 40000 unknown process exits"
generate_unknown_exits 40000

# Start a matching process after the churn. Its successful socket probe is also
# an event-loop barrier: pmark must consume the earlier exit events first.
probe_socket_mark || fail "a matching process was not marked after exit churn"

tombstones="$(state | jq -er '.dynamic.process_map.tombstones')"
if ((tombstones > 2)); then
	fail "unknown exits created $tombstones tombstones"
fi

E2E_RUNTIME="$E2E_RUNTIME" E2E_EXPECTED_FWMARK=0x414c4d01 \
	e2e-churn - <<'PY' >"$E2E_RUNTIME/live-target.log" 2>&1 &
import os
import pathlib
import socket
import time

runtime = pathlib.Path(os.environ["E2E_RUNTIME"])
expected = int(os.environ["E2E_EXPECTED_FWMARK"], 0)


def marked_socket():
    deadline = time.monotonic() + 20
    observed = 0
    while time.monotonic() <= deadline:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        observed = probe.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
        if observed == expected:
            return probe
        probe.close()
        time.sleep(0.02)
    raise SystemExit(f"socket mark was {observed:#010x}; expected {expected:#010x}")


initial = marked_socket()
runtime.joinpath("live-ready").touch()
deadline = time.monotonic() + 20
while time.monotonic() <= deadline and not runtime.joinpath("live-check").exists():
    time.sleep(0.02)
if not runtime.joinpath("live-check").exists():
    raise SystemExit("timed out waiting for the liveness check")
if initial.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) != expected:
    raise SystemExit("the live process lost the mark on its existing socket")
marked_socket().close()
PY
target_pid="$!"

retry "$E2E_TIMEOUT" "live target readiness" test -f "$E2E_RUNTIME/live-ready" \
	|| fail "live target did not receive its initial mark"
retry "$E2E_TIMEOUT" "live target process entry" \
	process_value_matches "$target_pid" true 4705220377385631744 true \
	|| fail "live target is missing from the process map"

log "generating 2048 exits while a marked process remains alive"
generate_unknown_exits 2048
probe_socket_mark || fail "pmark did not process the liveness barrier"
touch "$E2E_RUNTIME/live-check"
if ! wait "$target_pid"; then
	target_pid=""
	fail "live target lost its mark: $(cat "$E2E_RUNTIME/live-target.log" 2>/dev/null || true)"
fi
target_pid=""

log "case passed"
