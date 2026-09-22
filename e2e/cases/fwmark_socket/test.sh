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

start_daemon \
	-fwmark \
	-fmark-value 0x1a2b3c4d \
	-rule-comm '^never-match$'

E2E_RUNTIME="$E2E_RUNTIME" E2E_EXPECTED_FWMARK=0x1a2b3c4d \
	e2e-fwmark - <<'PY' >"$E2E_RUNTIME/target.log" 2>&1 &
import os
import pathlib
import socket
import time

runtime = pathlib.Path(os.environ["E2E_RUNTIME"])
expected = int(os.environ["E2E_EXPECTED_FWMARK"], 0)
existing = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if existing.getsockopt(socket.SOL_SOCKET, socket.SO_MARK) != 0:
    raise SystemExit("socket was marked before the rule matched")
runtime.joinpath("ready").touch()


def wait_file(name):
    deadline = time.monotonic() + 20
    path = runtime / name
    while time.monotonic() <= deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise SystemExit(f"timed out waiting for {name}")


def wait_mark(sock, wanted, description):
    deadline = time.monotonic() + 20
    observed = None
    while time.monotonic() <= deadline:
        observed = sock.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
        if observed == wanted:
            return
        time.sleep(0.02)
    raise SystemExit(
        f"{description} was {observed:#010x}; expected {wanted:#010x}"
    )


wait_file("check-marked")
wait_mark(existing, expected, "existing socket mark")
created_after_match = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
wait_mark(created_after_match, expected, "new socket mark")
runtime.joinpath("marked").touch()

wait_file("check-cleared")
wait_mark(existing, 0, "cleared existing socket mark")
wait_mark(created_after_match, 0, "cleared new socket mark")
PY
target_pid="$!"

retry "$E2E_TIMEOUT" "socket probe readiness" test -f "$E2E_RUNTIME/ready" \
	|| fail "socket probe did not become ready"

update_rules '{"rule_comm":"^e2e-fwmark$","rule_cmd":"","rule_exe":"","rule_ppid":"","mark_priority":5,"mark_value":1885667170394832896}' >/dev/null
retry "$E2E_TIMEOUT" "fwmark process entry" \
	process_value_matches "$target_pid" true 1885667170394832896 true \
	|| fail "socket probe did not receive a process mark"
touch "$E2E_RUNTIME/check-marked"
retry "$E2E_TIMEOUT" "socket marks" test -f "$E2E_RUNTIME/marked" \
	|| fail "socket marks were not applied: $(cat "$E2E_RUNTIME/target.log" 2>/dev/null || true)"

update_rules '{"rule_comm":"","rule_cmd":"","rule_exe":"","rule_ppid":"","mark_priority":5,"mark_value":1885667170394832896}' >/dev/null
retry "$E2E_TIMEOUT" "fwmark process entry removal" \
	process_value_matches "$target_pid" false \
	|| fail "socket probe process mark was not removed"
touch "$E2E_RUNTIME/check-cleared"
if ! wait "$target_pid"; then
	target_pid=""
	fail "socket probe failed: $(cat "$E2E_RUNTIME/target.log" 2>/dev/null || true)"
fi
target_pid=""

log "case passed"
