// Package multirule provides a userspace-only rule tracker for pmark process
// callbacks.
//
// A Tracker maintains an in-memory mapping from pmark.ProcessKey to the set of
// registered rule IDs matched by that process, plus a best-effort PID-to-latest
// ProcessKey index for convenience lookups. Registering a rule checks all
// currently tracked processes and propagates the new rule ID to already tracked
// descendants of every direct match. Observing a process checks all current
// rules and inherits any rule IDs associated with the latest known parent
// process.
//
// To attach it to a pmark Daemon, pass Tracker.CheckCallback as
// a Callbacks.Check or install it later with Daemon.SetChecker.
// The callback returns ok=false, so pmark marks are not created by the tracker.
// If ProcessEvent callbacks are available, attach Tracker.ProcessEventCallback
// as well so exit events can remove process lifetimes from the userspace map.
//
// PID-only lookups use the latest ProcessKey observed for that PID. PIDs can be
// reused, so these helpers are intentionally less precise than ProcessKey-based
// lookups.
package multirule

import (
	"slices"
	"sync"

	pmark "github.com/asciimoth/p-mark"
)

// Rule decides whether a process directly matches a tracker rule.
//
// Rules are called synchronously from Tracker methods and daemon callbacks.
// They should be quick and must not call back into the same Tracker.
type Rule func(pmark.ProcessInfo) bool

// Tracker keeps a userspace process-to-rule-ID mirror.
//
// A Tracker does not load, pin, read, or write eBPF objects. Attach it to a
// pmark Daemon by installing CheckCallback as the daemon Check callback. If the
// daemon also emits ProcessEvent callbacks, attach ProcessEventCallback to let
// the tracker remove exited process lifetimes.
type Tracker struct {
	mu sync.RWMutex

	nextID uint64
	rules  map[uint64]Rule

	processes map[pmark.ProcessKey]processEntry
	latestPID map[uint32]pmark.ProcessKey
}

type processEntry struct {
	info pmark.ProcessInfo
	ids  map[uint64]struct{}
}

// New returns an empty Tracker.
func New() *Tracker {
	return &Tracker{
		nextID:    1,
		rules:     make(map[uint64]Rule),
		processes: make(map[pmark.ProcessKey]processEntry),
		latestPID: make(map[uint32]pmark.ProcessKey),
	}
}

// RegisterRule registers rule and returns its unique ID.
//
// Existing tracked processes are immediately checked against the new rule. When
// an existing process directly matches, the new rule ID is also propagated to
// already tracked descendants of that process. Later observed children inherit
// from their latest known parent as usual.
func (t *Tracker) RegisterRule(rule Rule) uint64 {
	if rule == nil {
		rule = func(pmark.ProcessInfo) bool { return false }
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	id := t.nextID
	t.nextID++
	if t.nextID == 0 {
		t.nextID = 1
	}
	for {
		if _, exists := t.rules[id]; !exists {
			break
		}
		id = t.nextID
		t.nextID++
		if t.nextID == 0 {
			t.nextID = 1
		}
	}

	t.rules[id] = rule
	children := t.childrenByParentLocked()
	var roots []pmark.ProcessKey
	for key, entry := range t.processes {
		if rule(entry.info) {
			if entry.ids == nil {
				entry.ids = make(map[uint64]struct{})
			}
			entry.ids[id] = struct{}{}
			t.processes[key] = entry
			roots = append(roots, key)
		}
	}
	t.propagateRuleToDescendantsLocked(id, roots, children)
	return id
}

// UnregisterRule removes ruleID from the rule set and from every process entry.
//
// It reports whether a registered rule was removed.
func (t *Tracker) UnregisterRule(ruleID uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.rules[ruleID]; !ok {
		return false
	}
	delete(t.rules, ruleID)
	for key, entry := range t.processes {
		delete(entry.ids, ruleID)
		t.processes[key] = entry
	}
	return true
}

// ApplyProcess checks info against registered rules, inherits rule IDs from its
// latest known parent process when present, and updates the tracker state.
func (t *Tracker) ApplyProcess(info pmark.ProcessInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.applyProcessLocked(info)
}

// CheckCallback returns a pmark CheckFunc that observes process information and
// always returns ok=false so the tracker does not create pmark/eBPF marks.
func (t *Tracker) CheckCallback() pmark.CheckFunc {
	return func(info pmark.ProcessInfo) (int8, uint64, bool) {
		t.ApplyProcess(info)
		return 0, 0, false
	}
}

// ApplyProcessEvent applies process-event side effects that are not visible
// through CheckCallback, currently exit cleanup.
func (t *Tracker) ApplyProcessEvent(event pmark.ProcessEvent) {
	if event.Type != "exit" {
		if event.Process.Key != (pmark.ProcessKey{}) {
			t.ApplyProcess(event.Process)
		}
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.processes, event.Key)
	if latest, ok := t.latestPID[event.Key.Tgid]; ok && latest == event.Key {
		delete(t.latestPID, event.Key.Tgid)
	}
}

// ProcessEventCallback returns a daemon ProcessEvent hook for ApplyProcessEvent.
func (t *Tracker) ProcessEventCallback() func(pmark.ProcessEvent) {
	return func(event pmark.ProcessEvent) {
		t.ApplyProcessEvent(event)
	}
}

// RuleIDs returns a stable snapshot of rule IDs associated with key.
func (t *Tracker) RuleIDs(key pmark.ProcessKey) []uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.processes[key]
	if !ok {
		return nil
	}
	return sortedIDs(entry.ids)
}

// RuleIDsByPID returns a stable snapshot of rule IDs associated with the latest
// ProcessKey observed for pid.
//
// PIDs can be reused. When multiple ProcessKeys have been observed for the same
// pid, the latest observed ProcessKey wins. If that ProcessKey is later removed
// by an exit ProcessEvent, the PID lookup is removed too.
func (t *Tracker) RuleIDsByPID(pid uint32) []uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, ok := t.latestPID[pid]
	if !ok {
		return nil
	}
	entry, ok := t.processes[key]
	if !ok {
		return nil
	}
	return sortedIDs(entry.ids)
}

// Matches reports whether key is associated with ruleID.
func (t *Tracker) Matches(key pmark.ProcessKey, ruleID uint64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	entry, ok := t.processes[key]
	if !ok {
		return false
	}
	_, ok = entry.ids[ruleID]
	return ok
}

// MatchesPID reports whether the latest ProcessKey observed for pid is
// associated with ruleID.
//
// PIDs can be reused. When multiple ProcessKeys have been observed for the same
// pid, the latest observed ProcessKey wins. If that ProcessKey is later removed
// by an exit ProcessEvent, the PID lookup is removed too.
func (t *Tracker) MatchesPID(pid uint32, ruleID uint64) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key, ok := t.latestPID[pid]
	if !ok {
		return false
	}
	entry, ok := t.processes[key]
	if !ok {
		return false
	}
	_, ok = entry.ids[ruleID]
	return ok
}

// Snapshot returns a deep copy of the current process-to-rule-ID mapping.
func (t *Tracker) Snapshot() map[pmark.ProcessKey][]uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	snapshot := make(map[pmark.ProcessKey][]uint64, len(t.processes))
	for key, entry := range t.processes {
		snapshot[key] = sortedIDs(entry.ids)
	}
	return snapshot
}

func (t *Tracker) applyProcessLocked(info pmark.ProcessInfo) {
	ids := make(map[uint64]struct{})
	if parentKey, ok := t.latestPID[info.PPID]; ok {
		for id := range t.processes[parentKey].ids {
			ids[id] = struct{}{}
		}
	}
	for id, rule := range t.rules {
		if rule(info) {
			ids[id] = struct{}{}
		}
	}

	t.processes[info.Key] = processEntry{
		info: info,
		ids:  ids,
	}
	t.latestPID[info.Key.Tgid] = info.Key
}

func (t *Tracker) childrenByParentLocked() map[pmark.ProcessKey][]pmark.ProcessKey {
	children := make(map[pmark.ProcessKey][]pmark.ProcessKey)
	for key, entry := range t.processes {
		parentKey, ok := t.latestPID[entry.info.PPID]
		if !ok {
			continue
		}
		children[parentKey] = append(children[parentKey], key)
	}
	return children
}

func (t *Tracker) propagateRuleToDescendantsLocked(ruleID uint64, roots []pmark.ProcessKey, children map[pmark.ProcessKey][]pmark.ProcessKey) {
	seen := make(map[pmark.ProcessKey]struct{}, len(roots))
	stack := append([]pmark.ProcessKey(nil), roots...)
	for len(stack) > 0 {
		key := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		for _, childKey := range children[key] {
			entry, ok := t.processes[childKey]
			if !ok {
				continue
			}
			if entry.ids == nil {
				entry.ids = make(map[uint64]struct{})
			}
			entry.ids[ruleID] = struct{}{}
			t.processes[childKey] = entry
			stack = append(stack, childKey)
		}
	}
}

func sortedIDs(ids map[uint64]struct{}) []uint64 {
	if len(ids) == 0 {
		return nil
	}

	out := make([]uint64, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
