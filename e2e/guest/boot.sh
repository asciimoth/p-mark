#!/usr/bin/env bash
set -eEuo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

boot_failed() {
	local exit_status="$?"
	trap - ERR
	echo "PMARK_GUEST_RESULT status=FAIL exit=$exit_status phase=setup" \
		>/dev/console
	/bin/busybox poweroff -f
	exit "$exit_status"
}
trap boot_failed ERR

mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mkdir -p /sys/fs/cgroup /sys/fs/bpf
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount -t bpf bpffs /sys/fs/bpf
ip link set lo up

exec </dev/console >/dev/console 2>&1

status=0
/e2e/guest/run-suite.sh || status=$?

sync
if ((status == 0)); then
	echo 'PMARK_GUEST_RESULT status=PASS'
else
	echo "PMARK_GUEST_RESULT status=FAIL exit=$status"
fi
/bin/busybox poweroff -f
