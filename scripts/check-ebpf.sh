#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_root="${TMPDIR:-/tmp}"

if [[ "$temp_root" != /* ]]; then
	echo "TMPDIR must be an absolute path" >&2
	exit 2
fi

output_dir="$(mktemp -d "$temp_root/pmark-ebpf-check.XXXXXX")"
cleanup() {
	if [[ -d "$output_dir" && "$output_dir" == "$temp_root"/pmark-ebpf-check.* ]]; then
		rm -rf -- "$output_dir"
	fi
}
trap cleanup EXIT

mkdir -p "$output_dir/fwmark"

for tool in bpf-clang clang-format clang-tidy; do
	if ! command -v "$tool" >/dev/null; then
		echo "required eBPF check tool is missing: $tool" >&2
		exit 2
	fi
done

cflags=(
	-Wall
	-Wextra
	-Werror
	-Wno-unused-parameter
	-Wformat=2
	-Wshadow
	-Wundef
)

cd "$repo_root"

clang-format --dry-run --Werror mark.c fwmark/fwmark.c

clang-tidy \
	--checks='-*,clang-analyzer-core.*,clang-analyzer-deadcode.*' \
	--warnings-as-errors='*' \
	--quiet \
	mark.c fwmark/fwmark.c -- \
	-target bpfel -O2 -mcpu=v1 "${cflags[@]}"

GOPACKAGE=pmark go tool bpf2go \
	-cc bpf-clang \
	-tags linux \
	-output-dir "$output_dir" \
	mark mark.c -- "${cflags[@]}"

(
	cd fwmark
	GOPACKAGE=fwmark go tool bpf2go \
		-cc bpf-clang \
		-tags linux \
		-output-dir "$output_dir/fwmark" \
		fwmark fwmark.c -- "${cflags[@]}"
)

stale=0
for path in \
	mark_bpfel.go \
	mark_bpfel.o \
	mark_bpfeb.go \
	mark_bpfeb.o \
	fwmark/fwmark_bpfel.go \
	fwmark/fwmark_bpfel.o \
	fwmark/fwmark_bpfeb.go \
	fwmark/fwmark_bpfeb.o; do
	if ! cmp -s "$path" "$output_dir/$path"; then
		echo "generated eBPF artifact is stale: $path" >&2
		stale=1
	fi
done

if ((stale != 0)); then
	echo "run 'just generate' and commit the generated artifacts" >&2
	exit 1
fi

echo "eBPF formatting, static analysis, compilation, and generated artifacts are valid"
