#!/usr/bin/env bash
set -euo pipefail

: "${E2E_CASE:?}"
: "${E2E_RUNTIME:?}"
: "${E2E_PIN_PATH:?}"
: "${E2E_DAEMON_LOG:?}"
: "${E2E_HTTP_URL:?}"

daemon_pid=""
E2E_TIMEOUT="${E2E_TIMEOUT:-20}"

log() {
	printf '[%s] %s\n' "$E2E_CASE" "$*" >&2
}

fail() {
	log "FAILED: $*"
	if [[ -f "$E2E_DAEMON_LOG" ]]; then
		log "pmark log follows"
		tail -200 "$E2E_DAEMON_LOG" >&2 || true
	fi
	exit 1
}

retry() {
	local timeout="$1"
	local description="$2"
	shift 2
	local deadline=$((SECONDS + timeout))
	local status=0
	while ((SECONDS <= deadline)); do
		"$@" && return 0
		status=$?
		sleep 0.05
	done
	log "timed out waiting for $description"
	return "$status"
}

api() {
	local path="${1:-}"
	shift || true
	curl --fail --silent --show-error --max-time 5 "$@" "$E2E_HTTP_URL$path"
}

state() {
	api /state
}

api_is_ready() {
	api /state >/dev/null 2>&1
}

setup_bpffs() {
	mkdir -p /sys/fs/bpf
	if ! awk '$2 == "/sys/fs/bpf" && $3 == "bpf" { found=1 } END { exit !found }' /proc/mounts; then
		if ! mount -t bpf bpffs /sys/fs/bpf 2>"$E2E_RUNTIME/bpffs.err"; then
			log "the e2e suite requires a bpffs mount"
			cat "$E2E_RUNTIME/bpffs.err" >&2
			exit 1
		fi
		touch "$E2E_RUNTIME/mounted-bpffs"
	fi
	rm -rf "$E2E_PIN_PATH"
}

start_daemon() {
	if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
		fail "pmark is already running"
	fi
	setup_bpffs
	: >"$E2E_DAEMON_LOG"
	log "starting pmark"
	pmark \
		-pin-path "$E2E_PIN_PATH" \
		-http-addr "${E2E_HTTP_URL#http://}" \
		"$@" \
		>"$E2E_DAEMON_LOG" 2>&1 &
	daemon_pid="$!"
	retry "$E2E_TIMEOUT" "pmark control API" api_is_ready \
		|| fail "pmark control API did not become ready"
}

stop_daemon() {
	if [[ -n "${daemon_pid:-}" ]]; then
		if kill -0 "$daemon_pid" 2>/dev/null; then
			log "stopping pmark"
			kill "$daemon_pid" 2>/dev/null || true
			local deadline=$((SECONDS + 10))
			while kill -0 "$daemon_pid" 2>/dev/null && ((SECONDS <= deadline)); do
				sleep 0.05
			done
			if kill -0 "$daemon_pid" 2>/dev/null; then
				kill -KILL "$daemon_pid" 2>/dev/null || true
			fi
		fi
		wait "$daemon_pid" 2>/dev/null || true
		daemon_pid=""
	fi
	rm -rf "$E2E_PIN_PATH"
	if [[ -f "$E2E_RUNTIME/mounted-bpffs" ]]; then
		umount /sys/fs/bpf 2>/dev/null || true
		rm -f "$E2E_RUNTIME/mounted-bpffs"
	fi
}

process_value_matches() {
	local pid="$1"
	local has_mark="$2"
	local mark="${3:-}"
	local explicit="${4:-}"
	local filter

	filter='.dynamic.process_map.entries[]?
		| select(.key.tgid == ($pid | tonumber))
		| select(.value.tombstone == false)
		| select(.value.has_mark == ($has_mark == "true"))'
	if [[ -n "$mark" ]]; then
		filter+=" | select(.value.mark == ($mark | tonumber))"
	fi
	if [[ -n "$explicit" ]]; then
		filter+=" | select(.value.explicit == (\$explicit == \"true\"))"
	fi
	state | jq -e \
		--arg pid "$pid" \
		--arg has_mark "$has_mark" \
		--arg mark "$mark" \
		--arg explicit "$explicit" \
		"$filter" >/dev/null
}

process_is_tombstone() {
	local pid="$1"
	state | jq -e --arg pid "$pid" '
		.dynamic.process_map.entries[]?
		| select(.key.tgid == ($pid | tonumber))
		| select(.value.tombstone == true)
	' >/dev/null
}

update_rules() {
	local json="$1"
	curl --fail --silent --show-error --max-time 5 \
		-X POST \
		-H 'Content-Type: application/json' \
		--data "$json" \
		"$E2E_HTTP_URL/rules"
}
