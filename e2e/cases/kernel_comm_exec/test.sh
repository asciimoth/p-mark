#!/usr/bin/env bash
set -euo pipefail

source /e2e/lib/common.sh

parent_pid=""
child_pid=""
daemon_suspended=0
pids=()

cleanup() {
	if ((daemon_suspended != 0)) && [[ -n "${daemon_pid:-}" ]]; then
		kill -CONT "$daemon_pid" 2>/dev/null || true
		daemon_suspended=0
	fi
	if [[ -n "$parent_pid" ]]; then
		kill "$parent_pid" 2>/dev/null || true
		wait "$parent_pid" 2>/dev/null || true
	fi
	if [[ -n "$child_pid" ]]; then
		kill "$child_pid" 2>/dev/null || true
	fi
	for pid in "${pids[@]}"; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	stop_daemon
}
trap cleanup EXIT

expected_mark=$((0x4d000001))
iterations=64

start_daemon \
	-fwmark \
	-fmark-value 0x4d000001 \
	-rule-comm '^e2e-kmatch$'

state | jq -e '
	.dynamic.kernel_policy.mode == "authoritative"
	and .dynamic.kernel_policy.rule_count == 1
	and .dynamic.kernel_policy.promoted_comm == ["^e2e-kmatch$"]
	and .dynamic.kernel_policy.fallback_rules == []
' >/dev/null || fail "exact comm policy is not authoritative"

E2E_RUNTIME="$E2E_RUNTIME" e2e-kmatch "$E2E_CASE_DIR/parent.py" \
	>"$E2E_RUNTIME/parent.log" 2>&1 &
parent_pid="$!"
retry "$E2E_TIMEOUT" "matching parent readiness" test -f "$E2E_RUNTIME/parent-ready" \
	|| fail "matching parent did not become ready"
retry "$E2E_TIMEOUT" "matching parent process mark" \
	process_value_matches "$parent_pid" true "$((expected_mark << 32))" true \
	|| fail "matching parent did not receive its kernel policy mark"

kill -STOP "$daemon_pid"
daemon_suspended=1

for _ in $(seq 1 "$iterations"); do
	E2E_RUNTIME="$E2E_RUNTIME" e2e-kmatch "$E2E_CASE_DIR/matched.py" \
		>>"$E2E_RUNTIME/matched.log" 2>&1 &
	pids+=("$!")
done
touch "$E2E_RUNTIME/fork-miss"
retry "$E2E_TIMEOUT" "inherited child fork" test -s "$E2E_RUNTIME/child-pid" \
	|| fail "matching parent did not fork its child"
child_pid="$(<"$E2E_RUNTIME/child-pid")"

status=0
for pid in "${pids[@]}"; do
	wait "$pid" || status=1
done
pids=()
if ! wait "$parent_pid"; then
	status=1
fi
parent_pid=""
child_pid=""
if ((status != 0)); then
	fail "socket probes failed while userspace event handling was stopped"
fi

if [[ ! -f "$E2E_RUNTIME/matched-marks" ]]; then
	fail "matching probes did not report socket marks"
fi
matched_count="$(wc -l <"$E2E_RUNTIME/matched-marks")"
if [[ "$matched_count" -ne "$iterations" ]]; then
	fail "matching probes reported $matched_count marks; expected $iterations"
fi
if awk -v expected="$expected_mark" '$1 != expected { exit 1 }' "$E2E_RUNTIME/matched-marks"; then
	:
else
	fail "a first socket did not have mark 0x4d000001: $(tr '\n' ' ' <"$E2E_RUNTIME/matched-marks")"
fi

if [[ "$(<"$E2E_RUNTIME/miss-mark")" != "0" ]]; then
	fail "authoritative miss kept a stale socket mark: $(<"$E2E_RUNTIME/miss-mark")"
fi

kill -CONT "$daemon_pid"
daemon_suspended=0
retry "$E2E_TIMEOUT" "resumed p-mark control API" api_is_ready \
	|| fail "p-mark did not resume after the synchronous exec checks"

log "case passed"
