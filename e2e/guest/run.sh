#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${E2E_GUEST_IMAGE:-pmark-e2e-guest:local}"
vm_timeout="${E2E_GUEST_TIMEOUT:-600}"
case_timeout="${E2E_GUEST_CASE_TIMEOUT:-180}"
memory="${E2E_GUEST_MEMORY:-2048M}"
cpus="${E2E_GUEST_CPUS:-2}"
artifact_root="${E2E_GUEST_ARTIFACT_DIR:-$repo_root/e2e/artifacts/guest}"
cache_root="${E2E_GUEST_CACHE_DIR:-$repo_root/e2e/.guest-cache}"
image_input_label="io.pmark.e2e.guest-input-sha256"

cd "$repo_root"

if [[ "$(uname -m)" != "x86_64" ]]; then
	echo "the guest runner currently supports x86_64 hosts only" >&2
	exit 2
fi
for value in "$vm_timeout" "$case_timeout" "$cpus"; do
	if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
		echo "timeouts and CPU count must be positive integers" >&2
		exit 2
	fi
done
for command in docker qemu-system-x86_64 timeout sha256sum; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "missing guest test prerequisite: $command" >&2
		exit 2
	fi
done

if (($# > 0)); then
	cases=("$@")
else
	cases=(daemon_lifecycle fwmark_socket kernel_comm_exec tombstone_churn)
fi
for case_name in "${cases[@]}"; do
	if [[ ! "$case_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
		|| [[ ! -d "e2e/cases/$case_name" ]]; then
		echo "unknown guest e2e case: $case_name" >&2
		exit 2
	fi
done

input_hash="$({
	find . \
		-path ./.git -prune -o \
		-path ./.direnv -prune -o \
		-path ./e2e/artifacts -prune -o \
		-path ./e2e/.guest-cache -prune -o \
		-type f -print0 \
		| sort -z \
		| while IFS= read -r -d '' path; do
			printf '%s\0%s\0' "$path" "$(stat -c '%f' "$path")"
			sha256sum --zero "$path"
		done
} | sha256sum | cut -d ' ' -f 1)"

cached_hash=""
[[ -f "$cache_root/input-sha256" ]] && cached_hash="$(<"$cache_root/input-sha256")"
if [[ "${E2E_GUEST_REBUILD:-0}" == "1" || "$cached_hash" != "$input_hash" \
	|| ! -s "$cache_root/kernel" || ! -s "$cache_root/initramfs.gz" ]]; then
	echo "==> guest e2e: building kernel and initramfs"
	docker build \
		--label "$image_input_label=$input_hash" \
		-f e2e/guest/Dockerfile -t "$image" .
	container_id="$(docker create "$image")"
	temporary_cache="$(mktemp -d "${TMPDIR:-/tmp}/pmark-guest-cache.XXXXXX")"
	cleanup_build() {
		docker rm --force "$container_id" >/dev/null 2>&1 || true
		rm -rf "$temporary_cache"
	}
	trap cleanup_build EXIT
	docker cp "$container_id:/guest-artifacts/." "$temporary_cache/"
	printf '%s\n' "$input_hash" >"$temporary_cache/input-sha256"
	mkdir -p "$cache_root"
	cp -a "$temporary_cache"/. "$cache_root"/
	rm -rf "$temporary_cache"
	docker rm "$container_id" >/dev/null
	container_id=""
	trap - EXIT
else
	echo "==> guest e2e: reusing cached kernel and initramfs"
fi

revision="$(git describe --always --dirty --tags 2>/dev/null || printf unknown)"
commit="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-${revision//\//-}"
mkdir -p "$artifact_root"
artifact_dir="$(mktemp -d "$artifact_root/$run_id.XXXXXX")"
cp "$cache_root/kernel-version.txt" "$artifact_dir/kernel-version.txt"
cp "$cache_root/kernel-config" "$artifact_dir/kernel-config"
printf 'description=%s\ncommit=%s\ninput_sha256=%s\n' \
	"$revision" "$commit" "$input_hash" >"$artifact_dir/source-revision.txt"
printf '%s\n' "cases=${cases[*]}" "vm_timeout=$vm_timeout" \
	"case_timeout=$case_timeout" "memory=$memory" "cpus=$cpus" \
	>"$artifact_dir/launch.txt"

accelerator=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
	accelerator=kvm
fi
printf 'accelerator=%s\n' "$accelerator" >>"$artifact_dir/launch.txt"
case_list="$(IFS=,; printf '%s' "${cases[*]}")"

echo "==> guest e2e: booting with $accelerator; artifacts: $artifact_dir"
qemu_status=0
set +e
timeout --foreground --kill-after=10 "$vm_timeout" \
	qemu-system-x86_64 \
		-accel "$accelerator" \
		-machine q35 \
		-cpu max \
		-smp "$cpus" \
		-m "$memory" \
		-nodefaults \
		-no-reboot \
		-nographic \
		-nic none \
		-serial stdio \
		-kernel "$cache_root/kernel" \
		-initrd "$cache_root/initramfs.gz" \
		-append "console=ttyS0 panic=-1 pmark.cases=$case_list pmark.case_timeout=$case_timeout" \
		2>&1 | tee "$artifact_dir/serial.log"
pipeline_status=("${PIPESTATUS[@]}")
set -e
qemu_status="${pipeline_status[0]}"

parsed_log="$artifact_dir/serial.normalized.log"
tr -d '\r' <"$artifact_dir/serial.log" >"$parsed_log"

awk '
	/^PMARK_CASE_RESULT / {
		name=""; status=""; exit_code=""
		for (i=2; i<=NF; i++) {
			split($i, part, "=")
			if (part[1] == "name") name=part[2]
			if (part[1] == "status") status=part[2]
			if (part[1] == "exit") exit_code=part[2]
		}
		print name "\t" status "\t" exit_code
	}
' "$parsed_log" >"$artifact_dir/case-results.tsv"
grep '^PMARK_CASE_EVIDENCE ' "$parsed_log" \
	| sed 's/^PMARK_CASE_EVIDENCE //' >"$artifact_dir/policy-evidence.jsonl" || true

expected_count="${#cases[@]}"
result_count="$(wc -l <"$artifact_dir/case-results.tsv")"
guest_pass_count="$(grep -c '^PMARK_GUEST_RESULT status=PASS$' "$parsed_log" || true)"
failed_count="$(awk -F '\t' '$2 != "PASS" {count++} END {print count+0}' "$artifact_dir/case-results.tsv")"
expected_case_names="$(printf '%s\n' "${cases[@]}")"
actual_case_names="$(awk -F '\t' '{print $1}' "$artifact_dir/case-results.tsv")"
rm -f "$parsed_log"
if ((qemu_status != 0 || result_count != expected_count || guest_pass_count != 1 || failed_count != 0)) \
	|| [[ "$actual_case_names" != "$expected_case_names" ]]; then
	echo "guest e2e failed: qemu=$qemu_status results=$result_count/$expected_count failed=$failed_count" >&2
	exit 1
fi

echo "==> guest e2e: PASS (${cases[*]})"
