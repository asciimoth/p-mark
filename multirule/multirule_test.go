package multirule

import (
	"reflect"
	"testing"

	pmark "github.com/asciimoth/p-mark"
)

func TestRegisterRuleTraversesExistingProcesses(t *testing.T) {
	tracker := New()
	firefox := proc(100, 1, 0, "firefox")
	bash := proc(101, 1, 0, "bash")

	tracker.ApplyProcess(firefox)
	tracker.ApplyProcess(bash)
	id := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "firefox"
	})

	if got := tracker.RuleIDs(firefox.Key); !reflect.DeepEqual(got, []uint64{id}) {
		t.Fatalf("RuleIDs(firefox) = %v, want [%d]", got, id)
	}
	if got := tracker.RuleIDs(bash.Key); len(got) != 0 {
		t.Fatalf("RuleIDs(bash) = %v, want empty", got)
	}
}

func TestRegisterRulePropagatesToExistingDescendants(t *testing.T) {
	tracker := New()
	parent := proc(110, 1, 0, "parent")
	child := proc(111, 1, 110, "child")
	grandchild := proc(112, 1, 111, "grandchild")

	tracker.ApplyProcess(parent)
	tracker.ApplyProcess(child)
	tracker.ApplyProcess(grandchild)

	id := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "parent"
	})

	for _, info := range []pmark.ProcessInfo{parent, child, grandchild} {
		if got := tracker.RuleIDs(info.Key); !reflect.DeepEqual(got, []uint64{id}) {
			t.Fatalf("RuleIDs(%s) = %v, want [%d]", info.Comm, got, id)
		}
	}
}

func TestRegisterRulePropagatesFromEachDirectMatchOnlyToDescendants(t *testing.T) {
	tracker := New()
	parent := proc(120, 1, 0, "parent")
	child := proc(121, 1, 120, "target")
	grandchild := proc(122, 1, 121, "grandchild")
	sibling := proc(123, 1, 120, "sibling")

	tracker.ApplyProcess(parent)
	tracker.ApplyProcess(child)
	tracker.ApplyProcess(grandchild)
	tracker.ApplyProcess(sibling)

	id := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "target"
	})

	for _, info := range []pmark.ProcessInfo{child, grandchild} {
		if got := tracker.RuleIDs(info.Key); !reflect.DeepEqual(got, []uint64{id}) {
			t.Fatalf("RuleIDs(%s) = %v, want [%d]", info.Comm, got, id)
		}
	}
	for _, info := range []pmark.ProcessInfo{parent, sibling} {
		if got := tracker.RuleIDs(info.Key); len(got) != 0 {
			t.Fatalf("RuleIDs(%s) = %v, want empty", info.Comm, got)
		}
	}
}

func TestApplyProcessChecksRulesAndInheritsFromParent(t *testing.T) {
	tracker := New()
	parentRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "parent"
	})
	childRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Cmdline == "worker"
	})

	parent := proc(200, 1, 0, "parent")
	child := proc(201, 1, 200, "child")
	child.Cmdline = "worker"

	tracker.ApplyProcess(parent)
	tracker.ApplyProcess(child)

	want := []uint64{parentRule, childRule}
	if got := tracker.RuleIDs(child.Key); !reflect.DeepEqual(got, want) {
		t.Fatalf("RuleIDs(child) = %v, want %v", got, want)
	}
	if !tracker.Matches(child.Key, parentRule) {
		t.Fatalf("child did not inherit parent rule")
	}
}

func TestPIDLookupsUseLatestObservedProcessKey(t *testing.T) {
	tracker := New()
	oldRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "old"
	})
	newRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "new"
	})

	oldInfo := proc(250, 1, 0, "old")
	newInfo := proc(250, 2, 0, "new")
	tracker.ApplyProcess(oldInfo)

	if got := tracker.RuleIDsByPID(250); !reflect.DeepEqual(got, []uint64{oldRule}) {
		t.Fatalf("RuleIDsByPID(old) = %v, want [%d]", got, oldRule)
	}
	if !tracker.MatchesPID(250, oldRule) {
		t.Fatalf("MatchesPID(oldRule) = false, want true")
	}

	tracker.ApplyProcess(newInfo)

	if got := tracker.RuleIDsByPID(250); !reflect.DeepEqual(got, []uint64{newRule}) {
		t.Fatalf("RuleIDsByPID(new) = %v, want [%d]", got, newRule)
	}
	if tracker.MatchesPID(250, oldRule) {
		t.Fatalf("MatchesPID(oldRule) = true, want false after PID reuse")
	}
	if !tracker.MatchesPID(250, newRule) {
		t.Fatalf("MatchesPID(newRule) = false, want true")
	}
}

func TestUnregisterRuleRemovesIDFromAllEntries(t *testing.T) {
	tracker := New()
	parentRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "parent"
	})
	childRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "child"
	})

	parent := proc(300, 1, 0, "parent")
	child := proc(301, 1, 300, "child")
	tracker.ApplyProcess(parent)
	tracker.ApplyProcess(child)

	if !tracker.UnregisterRule(parentRule) {
		t.Fatalf("UnregisterRule(%d) = false, want true", parentRule)
	}
	if tracker.Matches(parent.Key, parentRule) {
		t.Fatalf("parent still matches unregistered rule")
	}
	if got := tracker.RuleIDs(child.Key); !reflect.DeepEqual(got, []uint64{childRule}) {
		t.Fatalf("RuleIDs(child) = %v, want [%d]", got, childRule)
	}
	if tracker.UnregisterRule(parentRule) {
		t.Fatalf("second UnregisterRule(%d) = true, want false", parentRule)
	}
}

func TestSnapshotIsDeepCopyAndSorted(t *testing.T) {
	tracker := New()
	high := tracker.RegisterRule(func(info pmark.ProcessInfo) bool { return true })
	low := tracker.RegisterRule(func(info pmark.ProcessInfo) bool { return true })
	info := proc(400, 1, 0, "any")

	tracker.ApplyProcess(info)
	snapshot := tracker.Snapshot()
	snapshot[info.Key][0] = 999

	want := []uint64{high, low}
	if got := tracker.RuleIDs(info.Key); !reflect.DeepEqual(got, want) {
		t.Fatalf("RuleIDs() = %v, want %v", got, want)
	}
}

func TestCheckCallbackDoesNotMarkPmarkProcess(t *testing.T) {
	tracker := New()
	id := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "match"
	})

	priority, mark, ok := tracker.CheckCallback()(proc(500, 1, 0, "match"))
	if priority != 0 || mark != 0 || ok {
		t.Fatalf("CheckCallback() = (%d, %d, %v), want (0, 0, false)", priority, mark, ok)
	}
	if got := tracker.RuleIDs(proc(500, 1, 0, "match").Key); !reflect.DeepEqual(got, []uint64{id}) {
		t.Fatalf("RuleIDs() = %v, want [%d]", got, id)
	}
}

func TestProcessEventCallbackRemovesExitedProcess(t *testing.T) {
	tracker := New()
	tracker.RegisterRule(func(info pmark.ProcessInfo) bool { return true })
	info := proc(600, 1, 0, "match")
	tracker.ApplyProcess(info)

	tracker.ProcessEventCallback()(pmark.ProcessEvent{
		Type:    "exit",
		Key:     info.Key,
		Process: info,
	})

	if got := tracker.RuleIDs(info.Key); len(got) != 0 {
		t.Fatalf("RuleIDs(exited) = %v, want empty", got)
	}
	if got := tracker.RuleIDsByPID(info.Key.Tgid); len(got) != 0 {
		t.Fatalf("RuleIDsByPID(exited) = %v, want empty", got)
	}
	if tracker.MatchesPID(info.Key.Tgid, 1) {
		t.Fatalf("MatchesPID(exited) = true, want false")
	}
}

func TestProcessEventCallbackDoesNotRemoveNewerPIDMapping(t *testing.T) {
	tracker := New()
	oldRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "old"
	})
	newRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "new"
	})
	oldInfo := proc(610, 1, 0, "old")
	newInfo := proc(610, 2, 0, "new")

	tracker.ApplyProcess(oldInfo)
	tracker.ApplyProcess(newInfo)
	tracker.ApplyProcessEvent(pmark.ProcessEvent{
		Type:    "exit",
		Key:     oldInfo.Key,
		Process: oldInfo,
	})

	if got := tracker.RuleIDsByPID(610); !reflect.DeepEqual(got, []uint64{newRule}) {
		t.Fatalf("RuleIDsByPID(new after old exit) = %v, want [%d]", got, newRule)
	}
	if tracker.MatchesPID(610, oldRule) {
		t.Fatalf("MatchesPID(oldRule) = true, want false")
	}
	if !tracker.MatchesPID(610, newRule) {
		t.Fatalf("MatchesPID(newRule) = false, want true")
	}
}

func TestProcessEventCallbackRemovesLatestPIDMappingWithoutFallback(t *testing.T) {
	tracker := New()
	oldRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "old"
	})
	newRule := tracker.RegisterRule(func(info pmark.ProcessInfo) bool {
		return info.Comm == "new"
	})
	oldInfo := proc(620, 1, 0, "old")
	newInfo := proc(620, 2, 0, "new")

	tracker.ApplyProcess(oldInfo)
	tracker.ApplyProcess(newInfo)
	tracker.ApplyProcessEvent(pmark.ProcessEvent{
		Type:    "exit",
		Key:     newInfo.Key,
		Process: newInfo,
	})

	if got := tracker.RuleIDs(oldInfo.Key); !reflect.DeepEqual(got, []uint64{oldRule}) {
		t.Fatalf("RuleIDs(old key) = %v, want [%d]", got, oldRule)
	}
	if got := tracker.RuleIDsByPID(620); len(got) != 0 {
		t.Fatalf("RuleIDsByPID(latest exited) = %v, want empty", got)
	}
	if tracker.MatchesPID(620, newRule) {
		t.Fatalf("MatchesPID(newRule) = true, want false")
	}
}

func proc(pid uint32, start uint64, ppid uint32, comm string) pmark.ProcessInfo {
	return pmark.ProcessInfo{
		Key: pmark.ProcessKey{
			Tgid:      pid,
			StartTime: start,
		},
		PPID: ppid,
		Comm: comm,
	}
}
