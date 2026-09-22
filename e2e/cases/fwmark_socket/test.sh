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
import errno
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


def open_listener(family, host, description):
    listener = None
    try:
        listener = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((host, 0))
        listener.listen(1)
        return listener
    except OSError as exc:
        if listener is not None:
            listener.close()
        if family == socket.AF_INET6 and exc.errno in {
            errno.EAFNOSUPPORT,
            errno.EADDRNOTAVAIL,
            errno.EPROTONOSUPPORT,
        }:
            runtime.joinpath("ipv6-skipped").write_text(str(exc))
            return None
        raise SystemExit(f"cannot create {description} listener: {exc}") from exc


def check_connect_mark(family, host, before, after, description, iterations=1):
    listener = open_listener(family, host, description)
    if listener is None:
        return False
    try:
        for iteration in range(iterations):
            client = socket.socket(family, socket.SOCK_STREAM)
            accepted = None
            try:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, before)
                observed = client.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
                if observed != before:
                    raise SystemExit(
                        f"{description} mark before connect iteration {iteration} "
                        f"was {observed:#010x}; expected {before:#010x}"
                    )
                client.connect(listener.getsockname())
                accepted, _ = listener.accept()
                observed = client.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
                if observed != after:
                    raise SystemExit(
                        f"{description} mark after connect iteration {iteration} "
                        f"was {observed:#010x}; expected {after:#010x}"
                    )
            finally:
                client.close()
                if accepted is not None:
                    accepted.close()
    finally:
        listener.close()
    return True


wait_file("check-marked")
wait_mark(existing, expected, "existing socket mark")
created_after_match = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
wait_mark(created_after_match, expected, "new socket mark")

# Clear SO_MARK after socket creation. Only a connect hook can repair it before
# the first route lookup. Repeat this to cover regressions in both address
# families under normal scheduler variation.
check_connect_mark(
    socket.AF_INET,
    "127.0.0.1",
    0,
    expected,
    "IPv4 connect-time repair",
    iterations=100,
)
if check_connect_mark(
    socket.AF_INET6,
    "::1",
    0,
    expected,
    "IPv6 connect-time repair",
    iterations=100,
):
    runtime.joinpath("ipv6-checked").touch()
runtime.joinpath("marked").touch()

wait_file("check-cleared")
wait_mark(existing, 0, "cleared existing socket mark")
wait_mark(created_after_match, 0, "cleared new socket mark")

# A live process-map entry with HasMark=false must not change or reject a
# connection.
check_connect_mark(
    socket.AF_INET,
    "127.0.0.1",
    0,
    0,
    "unmarked IPv4 connect",
)
runtime.joinpath("cleared").touch()

wait_file("check-zero-derived")

# A nonzero pmark value can still derive fwmark zero. In this case, the connect
# hook must leave an existing socket mark unchanged and allow the connection.
sentinel = 0x76543210
check_connect_mark(
    socket.AF_INET,
    "127.0.0.1",
    sentinel,
    sentinel,
    "zero-derived IPv4 connect",
)
if runtime.joinpath("ipv6-checked").exists():
    check_connect_mark(
        socket.AF_INET6,
        "::1",
        sentinel,
        sentinel,
        "zero-derived IPv6 connect",
    )
runtime.joinpath("zero-derived").touch()
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
if [[ -f "$E2E_RUNTIME/ipv6-skipped" ]]; then
	log "IPv6 connect-time repair skipped: $(<"$E2E_RUNTIME/ipv6-skipped")"
else
	test -f "$E2E_RUNTIME/ipv6-checked" \
		|| fail "IPv6 connect-time repair did not run"
fi

update_rules '{"rule_comm":"","rule_cmd":"","rule_exe":"","rule_ppid":"","mark_priority":5,"mark_value":1885667170394832896}' >/dev/null
retry "$E2E_TIMEOUT" "fwmark process entry removal" \
	process_value_matches "$target_pid" false \
	|| fail "socket probe process mark was not removed"
touch "$E2E_RUNTIME/check-cleared"
retry "$E2E_TIMEOUT" "unmarked connection checks" test -f "$E2E_RUNTIME/cleared" \
	|| fail "unmarked connection checks failed: $(cat "$E2E_RUNTIME/target.log" 2>/dev/null || true)"

update_rules '{"rule_comm":"^e2e-fwmark$","rule_cmd":"","rule_exe":"","rule_ppid":"","mark_priority":5,"mark_value":1}' >/dev/null
retry "$E2E_TIMEOUT" "zero-derived fwmark process entry" \
	process_value_matches "$target_pid" true 1 true \
	|| fail "socket probe did not receive the zero-derived process mark"
touch "$E2E_RUNTIME/check-zero-derived"
retry "$E2E_TIMEOUT" "zero-derived connection checks" test -f "$E2E_RUNTIME/zero-derived" \
	|| fail "zero-derived connection checks failed: $(cat "$E2E_RUNTIME/target.log" 2>/dev/null || true)"
if ! wait "$target_pid"; then
	target_pid=""
	fail "socket probe failed: $(cat "$E2E_RUNTIME/target.log" 2>/dev/null || true)"
fi
target_pid=""

log "case passed"
