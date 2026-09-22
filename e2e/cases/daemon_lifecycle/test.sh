#!/usr/bin/env bash
set -euo pipefail

source /e2e/lib/common.sh

target_pid=""
child_pid=""

cleanup() {
	if [[ -n "$child_pid" ]]; then
		kill "$child_pid" 2>/dev/null || true
	fi
	if [[ -n "$target_pid" ]]; then
		kill "$target_pid" 2>/dev/null || true
		wait "$target_pid" 2>/dev/null || true
	fi
	stop_daemon
}
trap cleanup EXIT

process_has_rule() {
	local pid="$1"
	local rule_id="$2"
	state | jq -e --arg pid "$pid" --argjson rule "$rule_id" '
		.dynamic.processes[]?
		| select(.key.tgid == ($pid | tonumber))
		| select(.matched_rules | index($rule))
	' >/dev/null
}

start_daemon \
	-rule-comm '' \
	-rule-ppid "$$" \
	-mark-priority 7 \
	-mark-value 123456789

child_file="$E2E_RUNTIME/child.pid"
e2e-life -c '(echo "$BASHPID" >"$1"; while :; do read -r -t 1 _ || true; done) & wait' _ "$child_file" &
target_pid="$!"

retry "$E2E_TIMEOUT" "target child PID" test -s "$child_file" \
	|| fail "target did not create its child"
child_pid="$(<"$child_file")"

retry "$E2E_TIMEOUT" "explicit parent mark" \
	process_value_matches "$target_pid" true 123456789 true \
	|| fail "parent did not receive the explicit mark"
retry "$E2E_TIMEOUT" "inherited child mark" \
	process_value_matches "$child_pid" true 123456789 false \
	|| fail "child did not inherit the parent mark"

initial_generation="$(state | jq -er '.dynamic.generation')"
update_rules '{"rule_comm":"","rule_cmd":"","rule_exe":"","rule_ppid":"","mark_priority":7,"mark_value":123456789}' >/dev/null

retry "$E2E_TIMEOUT" "parent mark removal" \
	process_value_matches "$target_pid" false \
	|| fail "parent mark was not removed after the rule update"
retry "$E2E_TIMEOUT" "child mark removal" \
	process_value_matches "$child_pid" false \
	|| fail "child mark was not removed after the rule update"
next_generation="$(state | jq -er '.dynamic.generation')"
if ((next_generation <= initial_generation)); then
	fail "rule update did not advance the checker generation"
fi

update_rules "{\"rule_comm\":\"\",\"rule_cmd\":\"\",\"rule_exe\":\"\",\"rule_ppid\":\"$$\",\"mark_priority\":11,\"mark_value\":987654321}" >/dev/null
retry "$E2E_TIMEOUT" "replacement parent mark" \
	process_value_matches "$target_pid" true 987654321 true \
	|| fail "parent did not receive the replacement mark"
retry "$E2E_TIMEOUT" "replacement child mark" \
	process_value_matches "$child_pid" true 987654321 false \
	|| fail "child did not inherit the replacement mark"

rule_json="$(curl --fail --silent --show-error --max-time 5 \
	-X POST -H 'Content-Type: application/json' \
	--data '{"comm":"^e2e-life$"}' \
	"$E2E_HTTP_URL/multirules")"
rule_id="$(jq -er '.id' <<<"$rule_json")"
retry "$E2E_TIMEOUT" "dynamic multirule match" \
	process_has_rule "$target_pid" "$rule_id" \
	|| fail "dynamic multirule did not match the parent"

curl --fail --silent --show-error --max-time 5 \
	-X DELETE "$E2E_HTTP_URL/multirules/$rule_id" >/dev/null
if state | jq -e --argjson rule "$rule_id" \
	'.dynamic.processes[]?.matched_rules[]? | select(. == $rule)' >/dev/null; then
	fail "deleted multirule remains in the process snapshot"
fi

kill "$child_pid"
wait "$child_pid" 2>/dev/null || true
child_pid=""
wait "$target_pid" 2>/dev/null || true

retry "$E2E_TIMEOUT" "parent tombstone" process_is_tombstone "$target_pid" \
	|| fail "parent did not become a tombstone"
retry "$E2E_TIMEOUT" "child tombstone" process_is_tombstone "$(<"$child_file")" \
	|| fail "child did not become a tombstone"
target_pid=""

log "case passed"
