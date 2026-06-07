package pmark

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	// ebpf-to-userspace ring event codes
	eventFork = 1
	eventExit = 2
	eventExec = 3

	// DefaultTombCollectionEvents bounds tombstone cleanup work by doing it
	// after a fixed number of processed ring events instead of on every event.
	DefaultTombCollectionEvents = 1024

	// DefaultTombTTL is the grace period during which exited process identities
	// remain in both userspace and kernel mirrors as tombstones.
	DefaultTombTTL = time.Minute
)

var pinnedMapNames = []string{"processes", "events"}

// ProcessKey is the per-boot process-lifetime identity shared with BPF.
//
// TGID is the process ID. StartTime is /proc/<pid>/stat field 22 expressed in
// USER_HZ ticks since boot. The pair is used instead of TGID alone because PIDs
// can be reused after exit.
type ProcessKey = markProcessKey // public re-export from generated code

// ProcessValue is the effective mark state stored in the pinned process map.
//
// A missing map entry, a live value with HasMark false, and a Tombstone value
// all mean "unmarked" for policy purposes. Live no-mark entries are retained
// after a process had an effective mark once, allowing newer checker rules to
// remove a mark without losing the process lifetime record. Tombstones are
// retained for a short grace period after exit so late events for an old process
// lifetime do not revive stale marks. Tombstone collection is the only operation
// that physically deletes entries.
//
// The generated Inheritance field is true for an explicit/original mark chosen
// by Check and false for a mark inherited from a parent. HasMark gates whether
// Mark and Priority are currently meaningful and whether this value can be
// inherited. Generation records the checker generation that last reconciled the
// entry. When competing updates are merged, tombstones win first, higher
// generations win second, higher priorities win third, and timestamps order
// otherwise-equivalent values. Timestamp is in CLOCK_BOOTTIME nanoseconds and is
// also used to expire tombstones.
type ProcessValue = markProcessValue // public re-export from generated code

// ProcessInfo is the userspace-enriched process view passed to callbacks.
//
// During process-tree traversal it is read from /proc and normally includes
// PPID, Comm, Cmdline, and Exe. During fork and exit events the daemon first
// tries to refresh the data from /proc; if the process is already gone or the
// identity no longer matches, only Key, PPID, and Comm from the BPF event are
// guaranteed to be present. Cmdline and Exe may be empty in that case.
type ProcessInfo struct {
	Key     ProcessKey
	PPID    uint32
	Comm    string
	Cmdline string
	Exe     string
}

// CheckFunc decides whether a process should receive an explicit mark.
//
// It is called while the daemon walks the current /proc tree before attaching
// BPF programs, again immediately after attach to cover the race window, and on
// each fork event for the child process. It is not called on exit events.
//
// Returning (priority, mark, true) creates or refreshes an explicit live mark
// for the supplied process in the current checker generation. Returning (_, _,
// false) leaves the process unmarked unless it can inherit a live HasMark value
// from its parent. If the process already had an entry, the daemon keeps a live
// HasMark=false entry for the rest of that process lifetime. CheckFunc should
// be quick and must not call back into the same Daemon; after Run starts event
// processing, a blocked CheckFunc blocks ring-buffer consumption.
type CheckFunc func(ProcessInfo) (int8, uint64, bool)

// KernelMark is the BPF program's view of a process mark at event time.
type KernelMark struct {
	// HasMark reports whether BPF saw a live mark for the process.
	HasMark bool

	// Inherited reports whether the mark seen by BPF was inherited from a
	// parent rather than explicitly selected by Check.
	Inherited bool

	// Mark is meaningful when HasMark is true.
	Mark uint64

	// Priority is meaningful when HasMark is true. Higher values win when
	// userspace merges otherwise comparable process updates.
	Priority int8
}

// ProcessEvent describes a process transition that produced an effective mark
// state worth reporting.
//
// Type is "fork", "exec", "exit", or "unknown". Fork and exec events are
// reported only when the process has an effective live mark after userspace
// reconciliation: a BPF mark, an existing userspace mirror entry, a new Check
// match, or fork inheritance from a marked parent. Unmarked fork and exec events
// are intentionally suppressed. Exit events are reported when BPF saw a live
// mark or userspace had a live mirror entry for the exiting process; the Value
// is a tombstone. Unknown events are reported for unexpected BPF event types and
// may have nil Value.
//
// Process contains the best process metadata available at callback time.
// ParentKey is set for fork events and nil otherwise. Kernel is the raw BPF
// mark state from the event, before userspace Check and mirror reconciliation.
// Value is the effective userspace value after reconciliation; it is non-nil
// for reported fork and exit events.
type ProcessEvent struct {
	Type      string
	Key       ProcessKey
	ParentKey *ProcessKey
	Kernel    KernelMark
	Process   ProcessInfo
	Value     *ProcessValue
}

// ProcessUpdate is emitted after the userspace mirror and kernel map have been
// updated for a process key.
//
// Updates can come from initial traversal, fork handling, exec handling, exit
// tombstoning, or event reconciliation. They are not emitted for unchanged
// values, for suppressed unmarked events, or when old tombstones are physically
// deleted during periodic cleanup.
type ProcessUpdate struct {
	Key   ProcessKey
	Value ProcessValue
}

// Callbacks contains optional hooks used by Daemon.
//
// All callbacks are invoked synchronously by daemon code. Check and
// ProcessUpdate can run during Run before it returns because initial process
// traversal may create marks. After Run starts the event loop, Check,
// ProcessEvent, ProcessUpdate, and Logf can run on the event goroutine.
// Implementations should avoid long blocking work and should not call Stop,
// Close, or other methods that wait for the daemon from inside a callback.
type Callbacks struct {
	// Check selects explicit marks for processes. Nil means no process is
	// explicitly marked by userspace, though inheritance from existing marks can
	// still occur.
	Check CheckFunc

	// ProcessEvent observes fork, exec, exit, and unknown BPF events after
	// userspace reconciliation. It is for transition logging or side effects
	// that need event context such as ParentKey and Kernel.
	ProcessEvent func(ProcessEvent)

	// ProcessUpdate observes effective map state changes after the daemon has
	// attempted to write them to the kernel map. It is for consumers that care
	// about the current mark state rather than the transition that caused it.
	ProcessUpdate func(ProcessUpdate)

	// Logf receives recoverable daemon diagnostics such as parse errors,
	// traversal failures, map sync failures, and tombstone cleanup failures.
	Logf func(format string, args ...any)
}

// Daemon owns loaded eBPF objects, links, ring reader, and userspace mirror.
type Daemon struct {
	objs      markObjects
	marker    *marker
	pinPath   string
	rd        *ringbuf.Reader
	forkLink  link.Link
	exitLink  link.Link
	execLink  link.Link
	done      chan error
	stopOnce  sync.Once
	closeOnce sync.Once

	tombCollectionEvents uint64
	tombTTL              time.Duration
}

// ProcessMapState is a point-in-time view of the pinned process map plus procfs.
type ProcessMapState struct {
	Alive      int
	Tombstones int
	Latest     uint64
	Entries    map[ProcessKey]ProcessValue
	Procs      []ProcessInfo
}

// NewDaemon prepares a daemon instance. Call Run to attach programs and start
// consuming events, and Stop to detach and close resources.
func NewDaemon(
	pinPath string, callbacks Callbacks, tcev uint64, tttl time.Duration,
) (*Daemon, error) {
	if err := os.MkdirAll(pinPath, 0o755); err != nil {
		return nil, fmt.Errorf("create pin path %q: %w", pinPath, err)
	}
	if err := removePinnedMaps(pinPath, pinnedMapNames...); err != nil {
		return nil, fmt.Errorf("remove old pinned maps: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs markObjects
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinPath},
	}
	if err := loadMarkObjects(&objs, &opts); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	check := callbacks.Check
	if check == nil {
		check = func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false }
	}

	var tombCollectionEvents uint64 = DefaultTombCollectionEvents
	if tcev != 0 {
		tombCollectionEvents = tcev
	}

	tombTTL := DefaultTombTTL
	if tttl != 0 {
		tombTTL = tttl
	}

	d := &Daemon{
		objs:    objs,
		pinPath: pinPath,
		done:    make(chan error, 1),

		tombCollectionEvents: tombCollectionEvents,
		tombTTL:              tombTTL,
	}
	d.marker = &marker{
		processes:  objs.Processes,
		mirror:     make(map[ProcessKey]ProcessValue),
		check:      check,
		generation: 1,
		callbacks:  callbacks,

		tombTTL: tombTTL,
	}
	return d, nil
}

func (d *Daemon) Run() error {
	if d.rd != nil {
		return nil
	}

	if err := d.marker.traverseProcessTree(); err != nil {
		d.marker.logf("initial process traversal before attach: %v", err)
	}

	forkLink, err := link.AttachTracing(link.TracingOptions{
		Program:    d.objs.HandleSchedProcessFork,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return fmt.Errorf("attach sched_process_fork: %w", err)
	}
	d.forkLink = forkLink

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    d.objs.HandleSchedProcessExit,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		_ = d.forkLink.Close()
		d.forkLink = nil
		return fmt.Errorf("attach sched_process_exit: %w", err)
	}
	d.exitLink = exitLink

	execLink, err := link.AttachTracing(link.TracingOptions{
		Program:    d.objs.HandleSchedProcessExec,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		_ = d.exitLink.Close()
		_ = d.forkLink.Close()
		d.exitLink = nil
		d.forkLink = nil
		return fmt.Errorf("attach sched_process_exec: %w", err)
	}
	d.execLink = execLink

	if err := d.marker.traverseProcessTree(); err != nil {
		d.marker.logf("initial process traversal after attach: %v", err)
	}

	rd, err := ringbuf.NewReader(d.objs.Events)
	if err != nil {
		_ = d.execLink.Close()
		_ = d.exitLink.Close()
		_ = d.forkLink.Close()
		d.execLink = nil
		d.exitLink = nil
		d.forkLink = nil
		return fmt.Errorf("open ring buffer: %w", err)
	}
	d.rd = rd

	go d.runEvents()
	return nil
}

func (d *Daemon) Done() <-chan error {
	return d.done
}

// SetChecker installs a new checker, increments the checker generation,
// immediately traverses /proc with the new checker, and returns the resulting
// generation.
//
// Processes matched by the new checker receive live HasMark=true entries at the
// new generation. Existing live entries that no longer match and cannot inherit
// a live mark are updated to HasMark=false at the new generation and kept until
// that process exits and its tombstone is collected.
func (d *Daemon) SetChecker(check CheckFunc) (uint64, error) {
	if check == nil {
		check = func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false }
	}
	return d.marker.setChecker(check)
}

// SetProcessMark explicitly sets a live mark for one process lifetime.
//
// The mark is applied with the current checker generation and the same merge,
// kernel-sync, and ProcessUpdate behavior used for marks found in BPF events or
// returned by Check. Higher-priority, newer-generation, or tombstone values that
// already exist may still win according to the normal ProcessValue merge rules.
func (d *Daemon) SetProcessMark(key ProcessKey, priority int8, mark uint64) {
	d.marker.setProcessMark(key, priority, mark)
}

// ForceProcessTraversal immediately traverses /proc with the current checker.
//
// This is useful when a caller needs to refresh process state outside the
// daemon's normal startup, event, and cleanup ordering. It does not advance the
// checker generation.
func (d *Daemon) ForceProcessTraversal() error {
	return d.marker.traverseProcessTree()
}

// ForceBumpGeneration increments the checker generation, immediately traverses
// /proc with the current checker, and returns the resulting generation.
//
// It has the same reconciliation effect as SetChecker with the existing checker,
// but does not replace the checker function. Use it when the checker closes over
// proving state that changed internally and all live processes need re-checking.
func (d *Daemon) ForceBumpGeneration() (uint64, error) {
	return d.marker.bumpGeneration()
}

// CurrentGeneration returns the active checker generation.
func (d *Daemon) CurrentGeneration() uint64 {
	return d.marker.currentGeneration()
}

// UpdateHooks replaces the non-check callbacks used by the daemon.
//
// The Check field is intentionally ignored; use SetChecker so checker changes
// always advance the generation and trigger a full traversal. Existing in-flight
// callbacks are synchronous, so this method is best called from outside daemon
// callbacks.
func (d *Daemon) UpdateHooks(callbacks Callbacks) {
	d.marker.updateHooks(callbacks)
}

func (d *Daemon) Stop() error {
	var err error
	d.stopOnce.Do(func() {
		if d.rd != nil {
			err = d.rd.Close()
		}
		if doneErr := <-d.done; doneErr != nil && err == nil {
			err = doneErr
		}
		d.marker.replayProcessUpdates(func(_ ProcessKey, value ProcessValue) (ProcessValue, bool) {
			value.HasMark = false
			return value, true
		})
	})
	return err
}

func (d *Daemon) Close() error {
	var err error
	d.closeOnce.Do(func() {
		if d.rd != nil {
			err = errors.Join(err, d.rd.Close())
		}
		if d.exitLink != nil {
			err = errors.Join(err, d.exitLink.Close())
		}
		if d.execLink != nil {
			err = errors.Join(err, d.execLink.Close())
		}
		if d.forkLink != nil {
			err = errors.Join(err, d.forkLink.Close())
		}
		err = errors.Join(err, d.objs.Close())
		if d.pinPath != "" {
			err = errors.Join(err, removePinnedMaps(d.pinPath, pinnedMapNames...))
		}
	})
	return err
}

func (d *Daemon) runEvents() {
	var err error
	defer func() {
		err = errors.Join(err, d.Close())
		d.done <- err
		close(d.done)
	}()

	for {
		record, readErr := d.rd.Read()
		if readErr != nil {
			if errors.Is(readErr, ringbuf.ErrClosed) {
				return
			}
			d.marker.logf("reading ring buffer: %v", readErr)
			continue
		}

		var event markEvent
		if readErr := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); readErr != nil {
			d.marker.logf("parsing event: %v", readErr)
			continue
		}

		d.marker.handleEvent(event)
		d.marker.eventCounter++
		if d.marker.eventCounter >= d.tombCollectionEvents {
			d.marker.eventCounter = 0
			if collectErr := d.marker.collectTombstones(); collectErr != nil {
				d.marker.logf("collecting tombstones: %v", collectErr)
			}
		}
	}
}

// GrabProcessMapState reads the pinned processes map under pinPath.
func GrabProcessMapState(pinPath string) (ProcessMapState, error) {
	processes, err := ebpf.LoadPinnedMap(filepath.Join(pinPath, "processes"), nil)
	if err != nil {
		return ProcessMapState{}, fmt.Errorf("open pinned processes map: %w", err)
	}
	defer processes.Close() //nolint:errcheck

	return readProcessMapState(processes)
}

// marker owns the userspace mirror and all policy decisions around it.
type marker struct {
	mu           sync.Mutex
	processes    *ebpf.Map
	mirror       map[ProcessKey]ProcessValue
	check        CheckFunc
	generation   uint64
	callbacks    Callbacks
	eventCounter uint64

	tombTTL time.Duration
}

func readProcessMapState(processes *ebpf.Map) (ProcessMapState, error) {
	snapshot := ProcessMapState{
		Entries: make(map[ProcessKey]ProcessValue),
	}

	var key ProcessKey
	var value ProcessValue
	iter := processes.Iterate()
	for iter.Next(&key, &value) {
		snapshot.Entries[key] = value
		if value.Tombstone {
			snapshot.Tombstones++
		} else {
			snapshot.Alive++
		}
		if value.Timestamp > snapshot.Latest {
			snapshot.Latest = value.Timestamp
		}
	}
	if err := iter.Err(); err != nil {
		return ProcessMapState{}, fmt.Errorf("iterate process map: %w", err)
	}

	procs, err := listProcesses()
	if err != nil {
		return ProcessMapState{}, fmt.Errorf("list processes: %w", err)
	}
	snapshot.Procs = procs
	return snapshot, nil
}

// ListProcesses returns the current /proc process tree using the same process
// identity parsing as the daemon.
func ListProcesses() ([]ProcessInfo, error) {
	return listProcesses()
}

func removePinnedMaps(pinPath string, names ...string) error {
	/*
	 * Pinned maps survive process restarts. That is useful once the ABI is
	 * stable, but during development an old pinned map with the previous value
	 * layout makes LoadAndAssign fail before userspace can repair it. Startup
	 * unlinks the known pins so the freshly generated map definitions are used.
	 */
	for _, name := range names {
		path := filepath.Join(pinPath, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func (m *marker) handleEvent(event markEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	info := procInfoFromEvent(event)

	switch event.Type {
	case eventFork:
		var value ProcessValue
		hasValue := false

		/*
		 * BPF has already attempted inheritance before emitting the event. If it
		 * found no mark, userspace checks its mirror because another userspace
		 * path may have seeded the child during the race window. Then the normal
		 * check callback can still make the child explicit.
		 */
		if event.HasMark && event.Value.HasMark {
			value = event.Value
			hasValue = true
			m.upsertProcess(event.Key, value)
		} else if existing, ok := m.mirror[event.Key]; ok && !existing.Tombstone && existing.HasMark {
			value = existing
			hasValue = true
			m.syncKernel(event.Key, value)
		}

		if priority, mark, ok := m.check(info); ok {
			value = m.newProcessValue(priority, mark, true)
			hasValue = true
			m.upsertProcess(event.Key, value)
		} else if parentValue, ok := m.mirror[event.ParentKey]; ok && canInherit(parentValue) {
			inherited := parentValue
			inherited.Tombstone = false
			inherited.HasMark = true
			inherited.Inheritance = false
			inherited.Generation = m.generation
			inherited.Timestamp = nowBootNS()
			value = inherited
			hasValue = true
			m.upsertProcess(event.Key, inherited)
		} else if hasValue {
			value = m.newNoMarkProcessValue(value)
			m.upsertProcess(event.Key, value)
		} else if existing, ok := m.mirror[event.Key]; ok && !existing.Tombstone {
			value = m.newNoMarkProcessValue(existing)
			hasValue = true
			m.upsertProcess(event.Key, value)
		}

		if !hasValue || !value.HasMark {
			return
		}
		m.onProcessEvent(ProcessEvent{
			Type:      "fork",
			Key:       event.Key,
			ParentKey: ptrProcessKey(event.ParentKey),
			Kernel: KernelMark{
				HasMark:   event.HasMark,
				Inherited: event.HasMark && !event.Value.Inheritance,
				Mark:      event.Value.Mark,
				Priority:  event.Value.Priority,
			},
			Process: info,
			Value:   ptrProcessValue(value),
		})
	case eventExit:
		/*
		 * Exit marks become tombstones rather than deletes. Tombstones are kept
		 * in both mirrors until periodic collection so late events for the old
		 * process lifetime do not accidentally revive stale marks.
		 */
		value := event.Value
		old, ok := m.mirror[event.Key]
		logExit := event.HasMark || (ok && !old.Tombstone && old.HasMark)
		if ok {
			value = old
		}
		value.Tombstone = true
		value.Timestamp = maxU64(value.Timestamp, nowBootNS())
		m.upsertProcessWithLog(event.Key, value, logExit)
		if !logExit {
			return
		}
		m.onProcessEvent(ProcessEvent{
			Type: "exit",
			Key:  event.Key,
			Kernel: KernelMark{
				HasMark:   event.HasMark,
				Inherited: event.HasMark && !event.Value.Inheritance,
				Mark:      event.Value.Mark,
				Priority:  event.Value.Priority,
			},
			Process: info,
			Value:   ptrProcessValue(value),
		})
	case eventExec:
		value := event.Value
		hasValue := false

		if existing, ok := m.mirror[event.Key]; ok && !existing.Tombstone {
			value = existing
			hasValue = true
		} else if event.HasMark && event.Value.HasMark {
			value = event.Value
			hasValue = true
		}

		if priority, mark, ok := m.check(info); ok {
			value = m.newProcessValue(priority, mark, true)
			hasValue = true
			m.upsertProcess(event.Key, value)
		} else if hasValue {
			value = m.newNoMarkProcessValue(value)
			m.upsertProcess(event.Key, value)
		}

		if !hasValue || !value.HasMark {
			return
		}
		m.onProcessEvent(ProcessEvent{
			Type: "exec",
			Key:  event.Key,
			Kernel: KernelMark{
				HasMark:   event.HasMark,
				Inherited: event.HasMark && !event.Value.Inheritance,
				Mark:      event.Value.Mark,
				Priority:  event.Value.Priority,
			},
			Process: info,
			Value:   ptrProcessValue(value),
		})
	default:
		m.onProcessEvent(ProcessEvent{
			Type:    "unknown",
			Key:     event.Key,
			Process: info,
			Kernel: KernelMark{
				HasMark:   event.HasMark,
				Inherited: event.HasMark && !event.Value.Inheritance,
				Mark:      event.Value.Mark,
				Priority:  event.Value.Priority,
			},
		})
	}
}

func (m *marker) traverseProcessTree() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.traverseProcessTreeLocked()
}

func (m *marker) traverseProcessTreeLocked() error {
	procs, err := listProcesses()
	if err != nil {
		return err
	}

	byParent := make(map[uint32][]ProcessInfo)
	byPID := make(map[uint32]ProcessInfo)
	for _, proc := range procs {
		byPID[proc.Key.Tgid] = proc
		byParent[proc.PPID] = append(byParent[proc.PPID], proc)
	}
	for ppid := range byParent {
		sort.Slice(byParent[ppid], func(i, j int) bool {
			return byParent[ppid][i].Key.Tgid < byParent[ppid][j].Key.Tgid
		})
	}

	visited := make(map[uint32]bool, len(procs))
	var walk func(ProcessInfo, *ProcessValue)
	walk = func(info ProcessInfo, parentValue *ProcessValue) {
		if visited[info.Key.Tgid] {
			return
		}
		visited[info.Key.Tgid] = true

		var current *ProcessValue
		if priority, mark, ok := m.check(info); ok {
			value := m.newProcessValue(priority, mark, true)
			m.upsertProcess(info.Key, value)
			current = &value
		} else if parentValue != nil && m.canInheritCurrentGeneration(*parentValue) {
			value := *parentValue
			value.Tombstone = false
			value.HasMark = true
			value.Inheritance = false
			value.Generation = m.generation
			value.Timestamp = nowBootNS()
			m.upsertProcess(info.Key, value)
			current = &value
		} else if existing, ok := m.mirror[info.Key]; ok && !existing.Tombstone {
			value := m.newNoMarkProcessValue(existing)
			m.upsertProcess(info.Key, value)
			current = &value
		}

		for _, child := range byParent[info.Key.Tgid] {
			walk(child, current)
		}
	}

	for _, root := range byParent[0] {
		walk(root, nil)
	}
	for _, proc := range procs {
		if !visited[proc.Key.Tgid] {
			var parentValue *ProcessValue
			if parent, ok := byPID[proc.PPID]; ok {
				if value, marked := m.mirror[parent.Key]; marked && m.canInheritCurrentGeneration(value) {
					parentValue = &value
				}
			}
			walk(proc, parentValue)
		}
	}

	liveMarked := 0
	for _, value := range m.mirror {
		if !value.Tombstone && value.HasMark {
			liveMarked++
		}
	}
	m.logf("process traversal complete: procs=%d mirror_entries=%d live_marked=%d", len(procs), len(m.mirror), liveMarked)
	return nil
}

func (m *marker) setChecker(check CheckFunc) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.check = check
	return m.bumpGenerationLocked()
}

func (m *marker) setProcessMark(key ProcessKey, priority int8, mark uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.upsertProcess(key, m.newProcessValue(priority, mark, true))
}

func (m *marker) bumpGeneration() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.bumpGenerationLocked()
}

func (m *marker) bumpGenerationLocked() (uint64, error) {
	m.generation++
	if m.generation == 0 {
		m.generation = 1
	}
	return m.generation, m.traverseProcessTreeLocked()
}

func (m *marker) currentGeneration() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.generation
}

func (m *marker) updateHooks(callbacks Callbacks) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callbacks.ProcessEvent = callbacks.ProcessEvent
	m.callbacks.ProcessUpdate = callbacks.ProcessUpdate
	m.callbacks.Logf = callbacks.Logf
	m.replayProcessUpdatesLocked(func(_ ProcessKey, value ProcessValue) (ProcessValue, bool) {
		return value, !value.Tombstone
	})
}

func (m *marker) upsertProcess(key ProcessKey, next ProcessValue) {
	m.upsertProcessWithLog(key, next, true)
}

func (m *marker) upsertProcessWithLog(key ProcessKey, next ProcessValue, logUpdate bool) {
	if old, ok := m.mirror[key]; ok {
		next = preferProcessValue(old, next)
		if old == next {
			return
		}
	}

	m.mirror[key] = next
	m.syncKernel(key, next)
	if logUpdate {
		m.onProcessUpdate(key, next)
	}
}

func preferProcessValue(old, next ProcessValue) ProcessValue {
	/*
	 * Merge order is intentionally independent of event source. Tombstones win
	 * over live values first. For the same tombstone class, newer checker
	 * generations win over older generations so stale checker decisions cannot
	 * overwrite on-the-fly checker updates. Higher priorities win next.
	 * Explicit marks then win over inherited marks, and newer timestamps win
	 * when the state class is
	 * otherwise the same.
	 */
	if old.Tombstone != next.Tombstone {
		if old.Tombstone {
			return old
		}
		return next
	}
	if old.Generation != next.Generation {
		if old.Generation > next.Generation {
			return old
		}
		return next
	}
	if old.Priority != next.Priority {
		if old.Priority > next.Priority {
			return old
		}
		return next
	}
	if old.Inheritance != next.Inheritance {
		if old.Inheritance {
			return old
		}
		return next
	}
	if old.Timestamp > next.Timestamp {
		return old
	}
	return next
}

func (m *marker) syncKernel(key ProcessKey, value ProcessValue) {
	if m.processes == nil {
		return
	}
	if err := m.processes.Put(key, value); err != nil {
		m.logf("syncing kernel process map pid=%d start_time=%d: %v", key.Tgid, key.StartTime, err)
	}
}

func (m *marker) onProcessUpdate(key ProcessKey, value ProcessValue) {
	if m.callbacks.ProcessUpdate != nil {
		m.callbacks.ProcessUpdate(ProcessUpdate{Key: key, Value: value})
	}
}

func (m *marker) replayProcessUpdates(selectValue func(ProcessKey, ProcessValue) (ProcessValue, bool)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.replayProcessUpdatesLocked(selectValue)
}

func (m *marker) replayProcessUpdatesLocked(selectValue func(ProcessKey, ProcessValue) (ProcessValue, bool)) {
	if m.callbacks.ProcessUpdate == nil {
		return
	}
	for key, value := range m.mirror {
		if updateValue, ok := selectValue(key, value); ok {
			m.callbacks.ProcessUpdate(ProcessUpdate{Key: key, Value: updateValue})
		}
	}
}

func (m *marker) collectTombstones() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := nowBootNS() - uint64(m.tombTTL.Nanoseconds())
	keys := make([]ProcessKey, 0)
	for key, value := range m.mirror {
		if value.Tombstone && value.Timestamp < cutoff {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return m.regularCleanupLocked()
	}

	for _, key := range keys {
		delete(m.mirror, key)
	}

	if _, err := m.processes.BatchDelete(keys, nil); err != nil {
		for _, key := range keys {
			if deleteErr := m.processes.Delete(key); deleteErr != nil && !errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("batch delete failed with %v; fallback delete pid=%d start_time=%d: %w", err, key.Tgid, key.StartTime, deleteErr)
			}
		}
	}
	m.logf("collected tombstones: count=%d", len(keys))
	return m.regularCleanupLocked()
}

func (m *marker) regularCleanupLocked() error {
	if err := m.tombstoneDeadProcessesLocked(); err != nil {
		return err
	}
	if m.hasExpiredLiveGenerationLocked() {
		m.logf("expired checker generation found; rerunning process traversal")
		return m.traverseProcessTreeLocked()
	}
	return nil
}

func (m *marker) tombstoneDeadProcessesLocked() error {
	dead := make([]ProcessKey, 0)
	for key, value := range m.mirror {
		if value.Tombstone {
			continue
		}
		if !procMatchesKey(key) {
			dead = append(dead, key)
		}
	}
	if len(dead) == 0 {
		return nil
	}

	now := nowBootNS()
	for _, key := range dead {
		value := m.mirror[key]
		value.Tombstone = true
		value.Timestamp = maxU64(value.Timestamp, now)
		m.upsertProcess(key, value)
	}
	m.logf("tombstoned dead processes: count=%d", len(dead))
	return nil
}

func (m *marker) hasExpiredLiveGenerationLocked() bool {
	for _, value := range m.mirror {
		if !value.Tombstone && value.Generation < m.generation {
			return true
		}
	}
	return false
}

func (m *marker) onProcessEvent(event ProcessEvent) {
	if m.callbacks.ProcessEvent != nil {
		m.callbacks.ProcessEvent(event)
	}
}

func (m *marker) logf(format string, args ...any) {
	if m.callbacks.Logf != nil {
		m.callbacks.Logf(format, args...)
	}
}

func ptrProcessKey(key ProcessKey) *ProcessKey {
	if key.Tgid == 0 && key.StartTime == 0 {
		return nil
	}
	out := key
	return &out
}

func ptrProcessValue(value ProcessValue) *ProcessValue {
	if value == (ProcessValue{}) {
		return nil
	}
	out := value
	return &out
}

func (m *marker) newProcessValue(priority int8, mark uint64, explicit bool) ProcessValue {
	return ProcessValue{
		Tombstone:   false,
		Inheritance: explicit,
		HasMark:     true,
		Priority:    priority,
		Generation:  m.generation,
		Mark:        mark,
		Timestamp:   nowBootNS(),
	}
}

func (m *marker) newNoMarkProcessValue(old ProcessValue) ProcessValue {
	return ProcessValue{
		Tombstone:   false,
		Inheritance: old.Inheritance,
		HasMark:     false,
		Priority:    old.Priority,
		Generation:  m.generation,
		Mark:        old.Mark,
		Timestamp:   nowBootNS(),
	}
}

func canInherit(value ProcessValue) bool {
	return !value.Tombstone && value.HasMark
}

func (m *marker) canInheritCurrentGeneration(value ProcessValue) bool {
	return canInherit(value) && value.Generation == m.generation
}

func listProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	procs := make([]ProcessInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		info, err := readProcInfo(uint32(pid64))
		if err != nil {
			continue
		}
		procs = append(procs, info)
	}
	return procs, nil
}

func readProcInfo(pid uint32) (ProcessInfo, error) {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return ProcessInfo{}, err
	}
	ppid, startTime, err := parseProcStat(string(stat))
	if err != nil {
		return ProcessInfo{}, err
	}

	return ProcessInfo{
		Key: ProcessKey{
			Tgid:      pid,
			StartTime: startTime,
		},
		PPID:    ppid,
		Comm:    readProcText(pid, "comm"),
		Cmdline: readProcCmdline(pid),
		Exe:     readProcExe(pid),
	}, nil
}

func parseProcStat(stat string) (uint32, uint64, error) {
	/*
	 * /proc/<pid>/stat field 2 is comm in parentheses and may contain spaces, so
	 * split only after the final ')'. After that, fields[1] is ppid and
	 * fields[19] is original stat field 22, starttime.
	 *
	 * starttime is expressed in USER_HZ clock ticks since boot, not CPU cycles.
	 * It is stable across CPU frequency changes and independent of the kernel's
	 * scheduler tick rate. BPF produces the same unit from task->start_boottime.
	 * If userspace reads procfs from a different time namespace than the tasks
	 * observed by BPF, procfs may include a namespace boottime offset that BPF
	 * does not include; in that deployment, keys need namespace-aware adjustment.
	 */
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

func procInfoFromEvent(event markEvent) ProcessInfo {
	info, err := readProcInfo(event.Key.Tgid)
	if err == nil && info.Key.StartTime == event.Key.StartTime {
		return info
	}
	return ProcessInfo{
		Key:  event.Key,
		PPID: event.Ppid,
		Comm: int8String(event.Comm),
	}
}

func procMatchesKey(key ProcessKey) bool {
	info, err := readProcInfo(key.Tgid)
	return err == nil && info.Key.StartTime == key.StartTime
}

func readProcText(pid uint32, name string) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readProcCmdline(pid uint32) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "cmdline"))
	if err != nil {
		return ""
	}
	parts := bytes.Split(bytes.Trim(data, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) != 0 {
			out = append(out, string(part))
		}
	}
	return strings.Join(out, " ")
}

func readProcExe(pid uint32) string {
	exe, err := os.Readlink(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "exe"))
	if err != nil {
		return ""
	}
	return exe
}

func nowBootNS() uint64 {
	/*
	 * Process-value timestamps use CLOCK_BOOTTIME because BPF uses
	 * bpf_ktime_get_boot_ns(). Keeping userspace and BPF in the same boot-time
	 * domain makes tombstone TTL comparisons straightforward.
	 */
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return procUptimeNS()
	}
	return uint64(ts.Nano())
}

func procUptimeNS() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(seconds * float64(time.Second))
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func int8String(raw [16]int8) string {
	buf := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}

func CombineChecks(left, right CheckFunc) CheckFunc {
	return func(info ProcessInfo) (int8, uint64, bool) {
		leftPriority, leftMark, leftOK := left(info)
		rightPriority, rightMark, rightOK := right(info)
		switch {
		case leftOK && rightOK:
			if rightPriority > leftPriority {
				return rightPriority, rightMark, true
			}
			return leftPriority, leftMark, true
		case rightOK:
			return rightPriority, rightMark, true
		case leftOK:
			return leftPriority, leftMark, true
		default:
			return 0, 0, false
		}
	}
}
