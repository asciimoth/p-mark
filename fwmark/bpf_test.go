package fwmark

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestBPFCollectionSpec(t *testing.T) {
	spec, err := loadFwmark()
	if err != nil {
		t.Fatalf("loadFwmark() error = %v", err)
	}

	programs := []struct {
		name        string
		programType ebpf.ProgramType
		attachType  ebpf.AttachType
		section     string
	}{
		{"fwmark_sock_create", ebpf.CGroupSock, ebpf.AttachCGroupInetSockCreate, "cgroup/sock_create"},
		{"fwmark_connect4", ebpf.CGroupSockAddr, ebpf.AttachCGroupInet4Connect, "cgroup/connect4"},
		{"fwmark_connect6", ebpf.CGroupSockAddr, ebpf.AttachCGroupInet6Connect, "cgroup/connect6"},
	}
	if len(spec.Programs) != len(programs) {
		t.Fatalf("program count = %d, want %d", len(spec.Programs), len(programs))
	}
	for _, want := range programs {
		t.Run(want.name, func(t *testing.T) {
			program, ok := spec.Programs[want.name]
			if !ok {
				t.Fatalf("program %q is missing", want.name)
			}
			if program.Type != want.programType {
				t.Errorf("program type = %s, want %s", program.Type, want.programType)
			}
			if program.AttachType != want.attachType {
				t.Errorf("program attach type = %s, want %s", program.AttachType, want.attachType)
			}
			if program.SectionName != want.section {
				t.Errorf("program section = %q, want %q", program.SectionName, want.section)
			}
			if len(program.Instructions) == 0 {
				t.Error("program has no instructions")
			}
		})
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

func TestBPFConnectProgramsSetMarkAndFailClosed(t *testing.T) {
	spec, err := loadFwmark()
	if err != nil {
		t.Fatalf("loadFwmark() error = %v", err)
	}

	for _, name := range []string{"fwmark_connect4", "fwmark_connect6"} {
		t.Run(name, func(t *testing.T) {
			program := spec.Programs[name]
			if program == nil {
				t.Fatalf("program %q is missing", name)
			}

			setSockopt := -1
			for i, instruction := range program.Instructions {
				if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnSetsockopt {
					if setSockopt >= 0 {
						t.Fatal("program calls bpf_setsockopt more than once")
					}
					setSockopt = i
				}
			}
			if setSockopt < 0 {
				t.Fatal("program does not call bpf_setsockopt")
			}

			// The compiled return sequence saves the helper result, defaults to
			// allow (1), jumps over the deny branch only when the helper returned
			// zero, and otherwise returns deny (0).
			instructions := program.Instructions
			if len(instructions) <= setSockopt+4 {
				t.Fatal("program ends before the bpf_setsockopt result is checked")
			}
			saveResult := instructions[setSockopt+1]
			allow := instructions[setSockopt+2]
			allowOnSuccess := instructions[setSockopt+3]
			deny := instructions[setSockopt+4]
			if !isRegisterMove(saveResult, asm.R1, asm.R0) ||
				!isImmediateMove(allow, asm.R0, 1) ||
				allowOnSuccess.OpCode.JumpOp() != asm.JEq ||
				allowOnSuccess.OpCode.Source() != asm.ImmSource ||
				allowOnSuccess.Dst != asm.R1 ||
				allowOnSuccess.Constant != 0 ||
				allowOnSuccess.Offset == 0 ||
				!isImmediateMove(deny, asm.R0, 0) {
				t.Fatal("program does not deny a connection after bpf_setsockopt returns an error")
			}
		})
	}
}

func isRegisterMove(instruction asm.Instruction, dst, src asm.Register) bool {
	return instruction.OpCode.Class().IsALU() &&
		instruction.OpCode.ALUOp() == asm.Mov &&
		instruction.OpCode.Source() == asm.RegSource &&
		instruction.Dst == dst &&
		instruction.Src == src
}

func isImmediateMove(instruction asm.Instruction, dst asm.Register, constant int64) bool {
	return instruction.OpCode.Class().IsALU() &&
		instruction.OpCode.ALUOp() == asm.Mov &&
		instruction.OpCode.Source() == asm.ImmSource &&
		instruction.Dst == dst &&
		instruction.Constant == constant
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
