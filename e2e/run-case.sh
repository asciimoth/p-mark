#!/usr/bin/env bash
set -euo pipefail

case_name="${1:?case name is required}"
if [[ ! "$case_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
	echo "invalid e2e case name: $case_name" >&2
	exit 2
fi
source_dir="/e2e/cases/$case_name"

if [[ ! -d "$source_dir" ]]; then
	echo "unknown e2e case: $case_name" >&2
	exit 1
fi

export E2E_CASE="$case_name"
export E2E_CASE_SOURCE="$source_dir"
export E2E_RUNTIME="/tmp/pmark-e2e/$case_name"
export E2E_CASE_DIR="$E2E_RUNTIME/case"
export E2E_PIN_PATH="/sys/fs/bpf/pmark-e2e-$case_name"
export E2E_DAEMON_LOG="$E2E_RUNTIME/pmark.log"
export E2E_HTTP_URL="http://127.0.0.1:18050"

rm -rf "$E2E_RUNTIME"
mkdir -p "$E2E_CASE_DIR"
cp -a "$source_dir"/. "$E2E_CASE_DIR"/
cd "$E2E_CASE_DIR"

if [[ -x ./setup.sh ]]; then
	./setup.sh
elif [[ -f ./setup.sh ]]; then
	bash ./setup.sh
fi

if [[ ! -x ./test.sh ]]; then
	echo "$case_name/test.sh must exist and be executable" >&2
	exit 1
fi

./test.sh
