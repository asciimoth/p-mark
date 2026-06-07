package fwmark

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/asciimoth/p-mark"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	defaultCgroupPath = "/sys/fs/cgroup"
)

// Manager owns fwmark eBPF programs and the userspace socket reconciler.
type Manager struct {
	objs      fwmarkObjects
	links     []link.Link
	logf      func(format string, args ...any)
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type SocketMarkReport struct {
	FDs               int
	Sockets           int
	Marked            int
	AlreadyMarked     int
	PermissionSkipped int
}

// NewManager loads fwmark programs, reuses core's pinned processes map, and
// attaches cgroup hooks to the root cgroup.
func NewManager(pinPath string, logf func(format string, args ...any)) (*Manager, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	var objs fwmarkObjects
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}
	if err := loadFwmarkObjects(&objs, &opts); err != nil {
		return nil, fmt.Errorf("load fwmark eBPF objects: %w", err)
	}

	m := &Manager{
		objs: objs,
		logf: logf,
		stop: make(chan struct{}),
	}
	if err := m.attach(defaultCgroupPath); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func (m *Manager) attach(cgroupPath string) error {
	programs := []struct {
		name    string
		attach  ebpf.AttachType
		program *ebpf.Program
	}{
		{"cgroup/sock_create", ebpf.AttachCGroupInetSockCreate, m.objs.FwmarkSockCreate},
	}

	for _, item := range programs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  item.attach,
			Program: item.program,
		})
		if err != nil {
			return fmt.Errorf("attach %s to %s: %w", item.name, cgroupPath, err)
		}
		m.links = append(m.links, l)
	}
	return nil
}

func (m *Manager) Close() error {
	var err error
	m.closeOnce.Do(func() {
		if m.stop != nil {
			close(m.stop)
		}
		m.wg.Wait()
		for _, l := range m.links {
			err = errors.Join(err, l.Close())
		}
		m.links = nil
		err = errors.Join(err, m.objs.Close())
	})
	return err
}

// ProcessUpdateCallback returns a daemon ProcessUpdate hook which reconciles
// already-open sockets for updated live processes.
func (m *Manager) ProcessUpdateCallback() func(pmark.ProcessUpdate) {
	return func(update pmark.ProcessUpdate) {
		if err := m.ApplyProcessUpdate(update); err != nil {
			m.logf("fwmark process update pid=%d start_time=%d: %v", update.Key.Tgid, update.Key.StartTime, err)
		}
	}
}

func (m *Manager) ApplyProcessUpdate(update pmark.ProcessUpdate) error {
	return m.applyProcessUpdate(update, true)
}

func (m *Manager) applyProcessUpdate(update pmark.ProcessUpdate, logReport bool) error {
	if update.Value.Tombstone || !processMatchesKey(update.Key) {
		return nil
	}

	mark := uint32(0)
	if update.Value.HasMark {
		mark = FromMark(update.Value.Mark)
	}
	report, err := SetProcessSocketsMarkReport(update.Key.Tgid, mark)
	if logReport && (report.Marked > 0 || report.PermissionSkipped > 0) {
		m.logf(
			"fwmark reconciled pid=%d mark=%s fds=%d sockets=%d marked=%d already_marked=%d permission_skipped=%d",
			update.Key.Tgid,
			Format(mark),
			report.FDs,
			report.Sockets,
			report.Marked,
			report.AlreadyMarked,
			report.PermissionSkipped,
		)
	}
	return err
}

func (m *Manager) ReconcileMarkedProcesses() error {
	var errs error
	var key pmark.ProcessKey
	var value pmark.ProcessValue
	iter := m.objs.Processes.Iterate()
	for iter.Next(&key, &value) {
		if value.Tombstone || !value.HasMark {
			continue
		}
		errs = errors.Join(errs, m.applyProcessUpdate(pmark.ProcessUpdate{
			Key:   key,
			Value: value,
		}, true))
	}
	return errors.Join(errs, iter.Err())
}

// FromMark derives the Linux fwmark from the daemon mark. Keep this in sync
// with fwmark.c: higher 32 bits become the socket mark.
func FromMark(mark uint64) uint32 {
	return uint32(mark >> 32)
}

// ToMark derives the daemon mark from the Linux fwmark. Keep this in sync
// with fwmark.c: the socket mark becomes the higher 32 bits, leaving the
// lower 32 bits as 0.
func ToMark(fwmark uint32) uint64 {
	return uint64(fwmark) << 32
}

func Format(mark uint32) string {
	return fmt.Sprintf("0x%08x", mark)
}

// Parse converts a fwmark hex string (with or without "0x") back to a uint32.
func Parse(markStr string) (uint32, error) {
	markStr = strings.TrimSpace(markStr)

	// Strip optional "0x" or "0X" prefix
	if strings.HasPrefix(markStr, "0x") || strings.HasPrefix(markStr, "0X") {
		markStr = markStr[2:]
	}

	val, err := strconv.ParseUint(markStr, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(val), nil
}

func SetProcessSocketsMark(pid uint32, mark uint32) error {
	_, err := SetProcessSocketsMarkReport(pid, mark)
	return err
}

func SetProcessSocketsMarkReport(pid uint32, mark uint32) (SocketMarkReport, error) {
	var report SocketMarkReport

	fdNames, err := os.ReadDir(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "fd"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return report, nil
		}
		return report, fmt.Errorf("read fd directory: %w", err)
	}
	report.FDs = len(fdNames)

	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return report, nil
		}
		return report, fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(pidfd) //nolint:errcheck

	var errs error
	for _, fdName := range fdNames {
		targetFD, err := strconv.Atoi(fdName.Name())
		if err != nil {
			continue
		}
		result, err := setProcessFDMark(pidfd, targetFD, mark)
		switch result {
		case setFDMarkSocket:
			report.Sockets++
		case setFDMarkMarked:
			report.Sockets++
			report.Marked++
		case setFDMarkAlreadyMarked:
			report.Sockets++
			report.AlreadyMarked++
		case setFDMarkPermissionSkipped:
			report.PermissionSkipped++
		}
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("fd %d: %w", targetFD, err))
		}
	}
	return report, errs
}

type setFDMarkResult int

const (
	setFDMarkSkipped setFDMarkResult = iota
	setFDMarkSocket
	setFDMarkMarked
	setFDMarkAlreadyMarked
	setFDMarkPermissionSkipped
)

func setProcessFDMark(pidfd int, targetFD int, mark uint32) (setFDMarkResult, error) {
	fd, err := unix.PidfdGetfd(pidfd, targetFD, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return setFDMarkPermissionSkipped, nil
		}
		if errors.Is(err, unix.EBADF) {
			return setFDMarkSkipped, nil
		}
		return setFDMarkSkipped, fmt.Errorf("pidfd_getfd: %w", err)
	}
	defer unix.Close(fd) //nolint:errcheck

	if _, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil {
		if errors.Is(err, unix.ENOTSOCK) {
			return setFDMarkSkipped, nil
		}
		return setFDMarkSkipped, fmt.Errorf("get SO_TYPE: %w", err)
	}
	currentMark, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil {
		return setFDMarkSocket, fmt.Errorf("get SO_MARK: %w", err)
	}
	if uint32(currentMark) == mark {
		return setFDMarkAlreadyMarked, nil
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
		return setFDMarkSocket, fmt.Errorf("set SO_MARK: %w", err)
	}
	return setFDMarkMarked, nil
}

func processMatchesKey(key pmark.ProcessKey) bool {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(key.Tgid), 10), "stat"))
	if err != nil {
		return false
	}
	_, startTime, err := parseProcStat(string(stat))
	return err == nil && startTime == key.StartTime
}

func parseProcStat(stat string) (uint32, uint64, error) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return 0, 0, fmt.Errorf("malformed stat")
	}
	fields := strings.Fields(stat[end+2:])
	if len(fields) < 20 {
		return 0, 0, fmt.Errorf("short stat")
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return uint32(ppid), startTime, nil
}
