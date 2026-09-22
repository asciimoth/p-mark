package fwmark

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestBPFCollectionSpec(t *testing.T) {
	spec, err := loadFwmark()
	if err != nil {
		t.Fatalf("loadFwmark() error = %v", err)
	}

	if len(spec.Programs) != 1 {
		t.Fatalf("program count = %d, want 1", len(spec.Programs))
	}
	program, ok := spec.Programs["fwmark_sock_create"]
	if !ok {
		t.Fatal("program \"fwmark_sock_create\" is missing")
	}
	if program.Type != ebpf.CGroupSock {
		t.Errorf("program type = %s, want %s", program.Type, ebpf.CGroupSock)
	}
	if program.AttachType != ebpf.AttachCGroupInetSockCreate {
		t.Errorf("program attach type = %s, want %s", program.AttachType, ebpf.AttachCGroupInetSockCreate)
	}
	if program.SectionName != "cgroup/sock_create" {
		t.Errorf("program section = %q, want %q", program.SectionName, "cgroup/sock_create")
	}
	if len(program.Instructions) == 0 {
		t.Error("program has no instructions")
	}

	if len(spec.Maps) != 1 {
		t.Fatalf("map count = %d, want 1", len(spec.Maps))
	}
	processes, ok := spec.Maps["processes"]
	if !ok {
		t.Fatal("map \"processes\" is missing")
	}
	if processes.Type != ebpf.Hash {
		t.Errorf("processes map type = %s, want %s", processes.Type, ebpf.Hash)
	}
	if processes.KeySize != 16 {
		t.Errorf("processes map key size = %d, want 16", processes.KeySize)
	}
	if processes.ValueSize != 32 {
		t.Errorf("processes map value size = %d, want 32", processes.ValueSize)
	}
	if processes.MaxEntries != 32768 {
		t.Errorf("processes map max entries = %d, want 32768", processes.MaxEntries)
	}
	if processes.Pinning != ebpf.PinByName {
		t.Errorf("processes map pinning = %s, want %s", processes.Pinning, ebpf.PinByName)
	}
}

func TestBPFGeneratedMapTypeLayout(t *testing.T) {
	if got := unsafe.Sizeof(fwmarkProcessKey{}); got != 16 {
		t.Errorf("process_key size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(fwmarkProcessKey{}.StartTime); got != 8 {
		t.Errorf("process_key.start_time offset = %d, want 8", got)
	}
	if got := unsafe.Sizeof(fwmarkProcessValue{}); got != 32 {
		t.Errorf("process_value size = %d, want 32", got)
	}
	if got := unsafe.Offsetof(fwmarkProcessValue{}.Generation); got != 8 {
		t.Errorf("process_value.generation offset = %d, want 8", got)
	}
	if got := unsafe.Offsetof(fwmarkProcessValue{}.Mark); got != 16 {
		t.Errorf("process_value.mark offset = %d, want 16", got)
	}
	if got := unsafe.Offsetof(fwmarkProcessValue{}.Timestamp); got != 24 {
		t.Errorf("process_value.timestamp offset = %d, want 24", got)
	}
}
