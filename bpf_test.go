package pmark

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestBPFCollectionSpec(t *testing.T) {
	spec, err := loadMark()
	if err != nil {
		t.Fatalf("loadMark() error = %v", err)
	}

	wantPrograms := map[string]struct {
		section  string
		attachTo string
	}{
		"handle_sched_process_exec": {"tp_btf/sched_process_exec", "sched_process_exec"},
		"handle_sched_process_exit": {"tp_btf/sched_process_exit", "sched_process_exit"},
		"handle_sched_process_fork": {"tp_btf/sched_process_fork", "sched_process_fork"},
	}
	if len(spec.Programs) != len(wantPrograms) {
		t.Fatalf("program count = %d, want %d", len(spec.Programs), len(wantPrograms))
	}
	for name, want := range wantPrograms {
		program, ok := spec.Programs[name]
		if !ok {
			t.Errorf("program %q is missing", name)
			continue
		}
		if program.Type != ebpf.Tracing {
			t.Errorf("program %q type = %s, want %s", name, program.Type, ebpf.Tracing)
		}
		if program.SectionName != want.section {
			t.Errorf("program %q section = %q, want %q", name, program.SectionName, want.section)
		}
		if program.AttachTo != want.attachTo {
			t.Errorf("program %q attach target = %q, want %q", name, program.AttachTo, want.attachTo)
		}
		if len(program.Instructions) == 0 {
			t.Errorf("program %q has no instructions", name)
		}
	}

	assertBPFMapSpec(t, spec.Maps, "processes", ebpf.Hash, 16, 32, 32768)
	assertBPFMapSpec(t, spec.Maps, "comm_rules", ebpf.Hash, 24, 16, MaxKernelCommRules*2)
	assertBPFMapSpec(t, spec.Maps, "active_policy", ebpf.Array, 4, 16, 1)
	assertBPFMapSpec(t, spec.Maps, "events", ebpf.RingBuf, 0, 0, 1<<24)
	if len(spec.Maps) != 4 {
		t.Fatalf("map count = %d, want 4", len(spec.Maps))
	}
}

func TestBPFExecUpdatesProcessBeforeRingBufferReservation(t *testing.T) {
	spec, err := loadMark()
	if err != nil {
		t.Fatalf("loadMark() error = %v", err)
	}
	program := spec.Programs["handle_sched_process_exec"]
	if program == nil {
		t.Fatal("exec program is missing")
	}

	mapUpdate := -1
	ringReserve := -1
	for index, instruction := range program.Instructions {
		if !instruction.IsBuiltinCall() {
			continue
		}
		switch asm.BuiltinFunc(instruction.Constant) {
		case asm.FnMapUpdateElem:
			mapUpdate = index
		case asm.FnRingbufReserve:
			ringReserve = index
		}
	}
	if mapUpdate < 0 {
		t.Fatal("exec program does not update the process map")
	}
	if ringReserve < 0 {
		t.Fatal("exec program does not reserve a ring-buffer event")
	}
	if mapUpdate >= ringReserve {
		t.Fatalf("process map update instruction %d is not before ring-buffer reserve instruction %d", mapUpdate, ringReserve)
	}
}

func TestBPFGeneratedTypeLayout(t *testing.T) {
	if got := unsafe.Sizeof(markProcessKey{}); got != 16 {
		t.Errorf("process_key size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(markProcessKey{}.StartTime); got != 8 {
		t.Errorf("process_key.start_time offset = %d, want 8", got)
	}
	if got := unsafe.Sizeof(markProcessValue{}); got != 32 {
		t.Errorf("process_value size = %d, want 32", got)
	}
	if got := unsafe.Offsetof(markProcessValue{}.Generation); got != 8 {
		t.Errorf("process_value.generation offset = %d, want 8", got)
	}
	if got := unsafe.Offsetof(markProcessValue{}.Mark); got != 16 {
		t.Errorf("process_value.mark offset = %d, want 16", got)
	}
	if got := unsafe.Offsetof(markProcessValue{}.Timestamp); got != 24 {
		t.Errorf("process_value.timestamp offset = %d, want 24", got)
	}
	if got := unsafe.Sizeof(markEvent{}); got != 104 {
		t.Errorf("event size = %d, want 104", got)
	}
	if got := unsafe.Offsetof(markEvent{}.Value); got != 56 {
		t.Errorf("event.value offset = %d, want 56", got)
	}
	if got := unsafe.Offsetof(markEvent{}.Comm); got != 88 {
		t.Errorf("event.comm offset = %d, want 88", got)
	}
	if got := unsafe.Sizeof(markCommRuleKey{}); got != 24 {
		t.Errorf("comm_rule_key size = %d, want 24", got)
	}
	if got := unsafe.Offsetof(markCommRuleKey{}.Comm); got != 8 {
		t.Errorf("comm_rule_key.comm offset = %d, want 8", got)
	}
	if got := unsafe.Sizeof(markCommRuleValue{}); got != 16 {
		t.Errorf("comm_rule_value size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(markCommRuleValue{}.Mark); got != 8 {
		t.Errorf("comm_rule_value.mark offset = %d, want 8", got)
	}
	if got := unsafe.Sizeof(markKernelPolicyState{}); got != 16 {
		t.Errorf("kernel_policy_state size = %d, want 16", got)
	}
}

func assertBPFMapSpec(
	t *testing.T,
	maps map[string]*ebpf.MapSpec,
	name string,
	type_ ebpf.MapType,
	keySize uint32,
	valueSize uint32,
	maxEntries uint32,
) {
	t.Helper()

	mapSpec, ok := maps[name]
	if !ok {
		t.Errorf("map %q is missing", name)
		return
	}
	if mapSpec.Type != type_ {
		t.Errorf("map %q type = %s, want %s", name, mapSpec.Type, type_)
	}
	if mapSpec.KeySize != keySize {
		t.Errorf("map %q key size = %d, want %d", name, mapSpec.KeySize, keySize)
	}
	if mapSpec.ValueSize != valueSize {
		t.Errorf("map %q value size = %d, want %d", name, mapSpec.ValueSize, valueSize)
	}
	if mapSpec.MaxEntries != maxEntries {
		t.Errorf("map %q max entries = %d, want %d", name, mapSpec.MaxEntries, maxEntries)
	}
	if mapSpec.Pinning != ebpf.PinByName {
		t.Errorf("map %q pinning = %s, want %s", name, mapSpec.Pinning, ebpf.PinByName)
	}
}
