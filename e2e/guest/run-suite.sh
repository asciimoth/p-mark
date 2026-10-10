#!/usr/bin/env bash
set -uo pipefail

case_timeout="${E2E_GUEST_CASE_TIMEOUT:-180}"
default_cases=(daemon_lifecycle fwmark_socket kernel_comm_exec tombstone_churn)
cases=()

for argument in $(</proc/cmdline); do
	case "$argument" in
		pmark.cases=*) IFS=, read -r -a cases <<<"${argument#pmark.cases=}" ;;
		pmark.case_timeout=*) case_timeout="${argument#pmark.case_timeout=}" ;;
	esac
done
if ((${#cases[@]} == 0)); then
	cases=("${default_cases[@]}")
fi

export E2E_EVIDENCE_DIR=/tmp/pmark-evidence
mkdir -p "$E2E_EVIDENCE_DIR"

echo "PMARK_METADATA kernel=$(uname -r) arch=$(uname -m)"
echo "PMARK_METADATA uid=$(id -u) gid=$(id -g) groups=$(id -G)"
echo "PMARK_METADATA capabilities=$(awk '/^Cap(Prm|Eff|Bnd|Amb):/ {printf "%s=%s ", $1, $2}' /proc/self/status)"
echo "PMARK_METADATA cgroup=$(stat -fc %T /sys/fs/cgroup) bpffs=$(stat -fc %T /sys/fs/bpf)"
echo "PMARK_METADATA cases=${cases[*]} case_timeout=$case_timeout"

status=0
for case_name in "${cases[@]}"; do
	case_status=0
	echo "PMARK_CASE_BEGIN name=$case_name"
	timeout --foreground --kill-after=10 "$case_timeout" /e2e/run-case.sh "$case_name" \
		|| case_status=$?

	cleanup_status=0
	if pgrep -x pmark >/dev/null 2>&1; then
		echo "PMARK_CLEANUP_ERROR case=$case_name process=pmark"
		pkill -KILL -x pmark 2>/dev/null || true
		cleanup_status=1
	fi
	if find /sys/fs/bpf -mindepth 1 -name 'pmark-e2e-*' -print -quit | grep -q .; then
		echo "PMARK_CLEANUP_ERROR case=$case_name object=pin"
		cleanup_status=1
	fi
	if [[ "$(bpftool -j link show 2>/dev/null)" != "[]" ]]; then
		echo "PMARK_CLEANUP_ERROR case=$case_name object=bpf-link"
		bpftool link show 2>/dev/null || true
		cleanup_status=1
	fi
	if ((cleanup_status != 0 && case_status == 0)); then
		case_status=1
	fi

	if [[ -s "$E2E_EVIDENCE_DIR/$case_name.jsonl" ]]; then
		sed 's/^/PMARK_CASE_EVIDENCE /' "$E2E_EVIDENCE_DIR/$case_name.jsonl"
	fi
	if ((case_status == 0)); then
		echo "PMARK_CASE_RESULT name=$case_name status=PASS"
	else
		echo "PMARK_CASE_RESULT name=$case_name status=FAIL exit=$case_status"
		status=1
	fi
done

exit "$status"
