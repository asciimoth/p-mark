#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${E2E_IMAGE:-pmark-e2e:local}"
coverage_enabled="${E2E_COVERAGE:-0}"
coverage_dir="${E2E_COVERAGE_DIR:-$repo_root/e2e/coverage}"
coverpkg="${E2E_COVERPKG:-github.com/asciimoth/p-mark/...}"
jobs="${E2E_JOBS:-1}"
build_attempts="${E2E_BUILD_ATTEMPTS:-10}"
build_retry_delay="${E2E_BUILD_RETRY_DELAY:-1}"
build_retry_max_delay="${E2E_BUILD_RETRY_MAX_DELAY:-60}"
image_input_label="io.pmark.e2e.input-sha256"

cd "$repo_root"

for integer_setting in \
	"E2E_JOBS=$jobs" \
	"E2E_BUILD_ATTEMPTS=$build_attempts" \
	"E2E_BUILD_RETRY_DELAY=$build_retry_delay" \
	"E2E_BUILD_RETRY_MAX_DELAY=$build_retry_max_delay"; do
	setting_name="${integer_setting%%=*}"
	value="${integer_setting#*=}"
	if [[ ! "$value" =~ ^[0-9]+$ ]]; then
		echo "$setting_name must be a non-negative integer" >&2
		exit 2
	fi
done
if ((jobs == 0)); then
	echo "E2E_JOBS must be greater than zero" >&2
	exit 2
fi
if ((build_attempts == 0)); then
	echo "E2E_BUILD_ATTEMPTS must be greater than zero" >&2
	exit 2
fi

docker_build_with_retry() {
	local attempt=1
	local delay="$build_retry_delay"
	local status=0
	if ((delay > build_retry_max_delay)); then
		delay="$build_retry_max_delay"
	fi

	while true; do
		if docker build "$@"; then
			return 0
		else
			status=$?
		fi
		if ((attempt >= build_attempts)); then
			echo "docker build failed after $attempt attempts" >&2
			return "$status"
		fi
		echo "docker build attempt $attempt/$build_attempts failed; retrying in ${delay}s" >&2
		sleep "$delay"
		((attempt += 1))
		if ((delay < build_retry_max_delay)); then
			delay=$((delay * 2))
			if ((delay > build_retry_max_delay)); then
				delay="$build_retry_max_delay"
			fi
		fi
	done
}

hash_image_inputs() {
	local path
	{
		find . \
			-path ./.git -prune -o \
			-path ./e2e/coverage -prune -o \
			\( -type f -o -type l \) -print0 \
			| sort -z \
			| while IFS= read -r -d '' path; do
				printf '%s\0' "$path" "$(stat -c '%f' "$path")"
				if [[ -L "$path" ]]; then
					printf '%s\0' "$(readlink "$path")"
				else
					sha256sum --zero "$path"
				fi
			done
	} | sha256sum | cut -d ' ' -f 1
}

image_matches_inputs() {
	local input_hash="$1"
	local image_hash

	image_hash="$(docker image inspect \
		--format "{{ index .Config.Labels \"$image_input_label\" }}" \
		"$image" 2>/dev/null || true)"
	[[ "$image_hash" == "$input_hash" ]]
}

if (($# > 0)); then
	cases=("$@")
else
	mapfile -t cases < <(find e2e/cases -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
fi

if ((${#cases[@]} == 0)); then
	echo "no e2e cases found" >&2
	exit 1
fi
for case_name in "${cases[@]}"; do
	if [[ ! "$case_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
		echo "invalid e2e case name: $case_name" >&2
		exit 2
	fi
	if [[ ! -d "e2e/cases/$case_name" ]]; then
		echo "unknown e2e case: $case_name" >&2
		exit 2
	fi
done

build_args=()
coverage_inputs=()
if [[ "$coverage_enabled" == "1" ]]; then
	mkdir -p "$coverage_dir"
	rm -rf "$coverage_dir/raw"
	rm -f "$coverage_dir/coverage.out" "$coverage_dir/functions.txt" "$coverage_dir/summary.txt" "$coverage_dir/total.txt"
	mkdir -p "$coverage_dir/raw"
	build_args=(
		--build-arg E2E_COVERAGE=1
		--build-arg "E2E_COVERPKG=$coverpkg"
	)
	echo "==> e2e coverage output: $coverage_dir"
fi

input_hash="$({
	hash_image_inputs
	printf '%s\0' "${build_args[@]}"
} | sha256sum | cut -d ' ' -f 1)"
if [[ "${E2E_REBUILD:-0}" != "1" ]] && image_matches_inputs "$input_hash"; then
	echo "==> e2e: reusing unchanged image $image"
else
	docker_build_with_retry "${build_args[@]}" \
		--label "$image_input_label=$input_hash" \
		-f e2e/Dockerfile -t "$image" .
fi

run_dir="$(mktemp -d "${TMPDIR:-/tmp}/pmark-e2e-run.XXXXXX")"
declare -A running_cases=()
case_logs=()
case_cidfiles=()
case_coverage_dirs=()

cleanup() {
	local exit_status="$?"
	local cidfile
	local container_id
	local pid

	trap - EXIT INT TERM
	for pid in "${!running_cases[@]}"; do
		kill "$pid" 2>/dev/null || true
	done
	for pid in "${!running_cases[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
	for cidfile in "$run_dir"/*.cid; do
		[[ -f "$cidfile" ]] || continue
		container_id="$(<"$cidfile")"
		[[ -n "$container_id" ]] || continue
		docker rm --force "$container_id" >/dev/null 2>&1 || true
	done
	rm -rf "$run_dir"
	exit "$exit_status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM

run_case() {
	local case_index="$1"
	local case_name="${cases[$case_index]}"
	local docker_run_args=(--privileged --pid host)

	if [[ "$coverage_enabled" == "1" ]]; then
		docker_run_args+=(
			-e GOCOVERDIR=/e2e-coverage
			-v "${case_coverage_dirs[$case_index]}:/e2e-coverage"
		)
	fi
	# E2E_DOCKER_RUN_ARGS is intended for local diagnostics, such as adding a
	# bind mount. Word splitting is intentional for this override.
	# shellcheck disable=SC2086
	docker run --rm --cidfile "${case_cidfiles[$case_index]}" \
		${E2E_DOCKER_RUN_ARGS:-} "${docker_run_args[@]}" "$image" "$case_name"
}

for case_index in "${!cases[@]}"; do
	if [[ "$coverage_enabled" == "1" ]]; then
		case_coverage_dirs[case_index]="$coverage_dir/raw/${cases[$case_index]}"
		mkdir -p "${case_coverage_dirs[$case_index]}"
		coverage_inputs+=("${case_coverage_dirs[$case_index]}")
	fi
done

next_case=0
failure_count=0
failed_cases=()

while ((next_case < ${#cases[@]} || ${#running_cases[@]} > 0)); do
	while ((next_case < ${#cases[@]} && ${#running_cases[@]} < jobs)); do
		case_name="${cases[$next_case]}"
		case_logs[next_case]="$run_dir/$next_case.log"
		case_cidfiles[next_case]="$run_dir/$next_case.cid"
		echo "==> e2e: starting $case_name"
		run_case "$next_case" >"${case_logs[$next_case]}" 2>&1 &
		running_cases[$!]="$next_case"
		((next_case += 1))
	done

	completed_pid=""
	case_status=0
	if wait -n -p completed_pid "${!running_cases[@]}"; then
		case_status=0
	else
		case_status=$?
	fi
	completed_index="${running_cases[$completed_pid]}"
	case_name="${cases[$completed_index]}"
	cat "${case_logs[$completed_index]}"
	if ((case_status == 0)); then
		echo "==> e2e: PASS $case_name"
	else
		echo "==> e2e: FAIL $case_name (exit $case_status)" >&2
		failed_cases+=("$case_name")
		((failure_count += 1))
	fi
	unset 'running_cases[$completed_pid]'
done

if ((failure_count > 0)); then
	echo "e2e failed: ${failed_cases[*]}" >&2
	exit 1
fi

if [[ "$coverage_enabled" == "1" ]]; then
	input_dirs="$(IFS=,; printf '%s' "${coverage_inputs[*]}")"
	go tool covdata percent -i="$input_dirs" | tee "$coverage_dir/summary.txt"
	go tool covdata textfmt -i="$input_dirs" -o "$coverage_dir/coverage.out"
	go tool cover -func="$coverage_dir/coverage.out" >"$coverage_dir/functions.txt"
	tail -1 "$coverage_dir/functions.txt" | tee "$coverage_dir/total.txt"
fi
