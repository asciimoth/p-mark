#!/usr/bin/env bash
set -euo pipefail

output=/guest-artifacts
kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' | sort -V | tail -1)"
version="${kernel##*/vmlinuz-}"
config="/boot/config-$version"

if [[ ! -f "$kernel" || ! -f "$config" ]]; then
	echo "the guest kernel or its configuration is missing" >&2
	exit 1
fi

mkdir -p "$output" /dev /proc /sys /run /tmp /sys/fs/bpf /sys/fs/cgroup
chmod 1777 /tmp
ln -sf /bin/busybox /init

printf '%s\n' "$version" >"$output/kernel-version.txt"
cp "$kernel" "$output/kernel"
cp "$config" "$output/kernel-config"

staging="$(mktemp -d /tmp/pmark-guest-root.XXXXXX)"
tar \
	--one-file-system \
	--exclude=./boot/'*' \
	--exclude=./dev/'*' \
	--exclude=./guest-artifacts \
	--exclude=./proc/'*' \
	--exclude=./run/'*' \
	--exclude=./sys/'*' \
	--exclude=./tmp/'*' \
	--exclude=".${staging}" \
	--create --file=- --directory=/ . \
	| tar --extract --file=- --directory="$staging"
(
	cd "$staging"
	find . -xdev -print0 \
		| cpio --null --create --format=newc --quiet \
		| gzip -1 >"$output/initramfs.gz"
)
rm -rf "$staging"
