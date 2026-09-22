package pmark

import (
	"os"
	"strings"
	"testing"
)

func TestPreferProcessValueGenerationBeatsTimestamp(t *testing.T) {
	old := ProcessValue{
		HasMark:    true,
		Generation: 2,
		Mark:       20,
		Timestamp:  10,
	}
	next := ProcessValue{
		HasMark:    true,
		Generation: 1,
		Mark:       10,
		Timestamp:  20,
	}

	got := preferProcessValue(old, next)
	if got != old {
		t.Fatalf("preferProcessValue() = %+v, want newer generation %+v", got, old)
	}
}

func TestPreferProcessValueTombstoneBeatsGeneration(t *testing.T) {
	old := ProcessValue{
		Tombstone:  true,
		Generation: 1,
		Timestamp:  10,
	}
	next := ProcessValue{
		HasMark:    true,
		Generation: 2,
		Timestamp:  20,
	}

	got := preferProcessValue(old, next)
	if got != old {
		t.Fatalf("preferProcessValue() = %+v, want tombstone %+v", got, old)
	}
}

func TestPreferProcessValuePriorityBeatsInheritanceAndTimestamp(t *testing.T) {
	old := ProcessValue{
		Inheritance: true,
		HasMark:     true,
		Priority:    1,
		Generation:  2,
		Mark:        20,
		Timestamp:   10,
	}
	next := ProcessValue{
		HasMark:    true,
		Priority:   2,
		Generation: 2,
		Mark:       10,
		Timestamp:  1,
	}

	got := preferProcessValue(old, next)
	if got != next {
		t.Fatalf("preferProcessValue() = %+v, want higher priority %+v", got, next)
	}
}

func TestPreferProcessValueOrdering(t *testing.T) {
	base := ProcessValue{
		HasMark:     true,
		Priority:    3,
		Generation:  4,
		Inheritance: false,
		Mark:        40,
		Timestamp:   50,
	}
	tests := []struct {
		name string
		old  ProcessValue
		next ProcessValue
		want ProcessValue
	}{
		{"next tombstone", base, func() ProcessValue { value := base; value.Tombstone = true; return value }(), func() ProcessValue { value := base; value.Tombstone = true; return value }()},
		{"old tombstone", func() ProcessValue { value := base; value.Tombstone = true; return value }(), base, func() ProcessValue { value := base; value.Tombstone = true; return value }()},
		{"next generation", base, func() ProcessValue { value := base; value.Generation++; return value }(), func() ProcessValue { value := base; value.Generation++; return value }()},
		{"old generation", func() ProcessValue { value := base; value.Generation++; return value }(), base, func() ProcessValue { value := base; value.Generation++; return value }()},
		{"next priority", base, func() ProcessValue { value := base; value.Priority++; return value }(), func() ProcessValue { value := base; value.Priority++; return value }()},
		{"explicit wins", base, func() ProcessValue { value := base; value.Inheritance = true; return value }(), func() ProcessValue { value := base; value.Inheritance = true; return value }()},
		{"new timestamp", base, func() ProcessValue { value := base; value.Timestamp++; return value }(), func() ProcessValue { value := base; value.Timestamp++; return value }()},
		{"equal selects next", base, base, base},
		{"mark state follows timestamp", base, func() ProcessValue { value := base; value.HasMark = false; value.Timestamp++; return value }(), func() ProcessValue { value := base; value.HasMark = false; value.Timestamp++; return value }()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferProcessValue(tc.old, tc.next); got != tc.want {
				t.Fatalf("preferProcessValue(%+v, %+v) = %+v, want %+v", tc.old, tc.next, got, tc.want)
			}
		})
	}
}

func TestCanInheritRequiresLiveMark(t *testing.T) {
	cases := []struct {
		name  string
		value ProcessValue
		want  bool
	}{
		{
			name:  "live mark",
			value: ProcessValue{HasMark: true},
			want:  true,
		},
		{
			name:  "live no mark",
			value: ProcessValue{HasMark: false},
			want:  false,
		},
		{
			name:  "tombstone with mark",
			value: ProcessValue{Tombstone: true, HasMark: true},
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canInherit(tc.value); got != tc.want {
				t.Fatalf("canInherit() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanInheritCurrentGenerationRejectsOldGeneration(t *testing.T) {
	m := &marker{generation: 3}

	cases := []struct {
		name  string
		value ProcessValue
		want  bool
	}{
		{
			name:  "current generation live mark",
			value: ProcessValue{HasMark: true, Generation: 3},
			want:  true,
		},
		{
			name:  "old generation live mark",
			value: ProcessValue{HasMark: true, Generation: 2},
			want:  false,
		},
		{
			name:  "current generation no mark",
			value: ProcessValue{HasMark: false, Generation: 3},
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.canInheritCurrentGeneration(tc.value); got != tc.want {
				t.Fatalf("canInheritCurrentGeneration() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHandleEventIgnoresUnknownExit(t *testing.T) {
	key := ProcessKey{Tgid: 999999, StartTime: 1001}
	updates := 0
	events := 0
	m := &marker{
		mirror: make(map[ProcessKey]ProcessValue),
		callbacks: Callbacks{
			ProcessUpdate: func(ProcessUpdate) { updates++ },
			ProcessEvent:  func(ProcessEvent) { events++ },
		},
	}

	m.handleEvent(markEvent{Type: eventExit, Key: key})

	if len(m.mirror) != 0 {
		t.Fatalf("mirror entries = %d, want 0", len(m.mirror))
	}
	if updates != 0 {
		t.Fatalf("ProcessUpdate calls = %d, want 0", updates)
	}
	if events != 0 {
		t.Fatalf("ProcessEvent calls = %d, want 0", events)
	}
}

func TestHandleEventTombstonesUserspaceTrackedExit(t *testing.T) {
	tests := []struct {
		name       string
		value      ProcessValue
		wantUpdate int
		wantEvent  int
	}{
		{
			name: "marked",
			value: ProcessValue{
				HasMark:    true,
				Generation: 3,
				Mark:       100,
				Timestamp:  1,
			},
			wantUpdate: 1,
			wantEvent:  1,
		},
		{
			name: "live no mark",
			value: ProcessValue{
				HasMark:    false,
				Generation: 4,
				Timestamp:  1,
			},
		},
	}

	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := ProcessKey{Tgid: uint32(999990 + index), StartTime: uint64(2001 + index)}
			updates := 0
			events := 0
			m := &marker{
				mirror: map[ProcessKey]ProcessValue{key: tc.value},
				callbacks: Callbacks{
					ProcessUpdate: func(ProcessUpdate) { updates++ },
					ProcessEvent:  func(ProcessEvent) { events++ },
				},
			}

			m.handleEvent(markEvent{Type: eventExit, Key: key})

			got, ok := m.mirror[key]
			if !ok {
				t.Fatalf("tracked process is missing from mirror")
			}
			if !got.Tombstone {
				t.Fatalf("Tombstone = false, want true")
			}
			if got.HasMark != tc.value.HasMark || got.Generation != tc.value.Generation || got.Mark != tc.value.Mark {
				t.Fatalf("tombstone = %+v, want tracked state from %+v", got, tc.value)
			}
			if got.Timestamp <= tc.value.Timestamp {
				t.Fatalf("Timestamp = %d, want greater than %d", got.Timestamp, tc.value.Timestamp)
			}
			if updates != tc.wantUpdate {
				t.Fatalf("ProcessUpdate calls = %d, want %d", updates, tc.wantUpdate)
			}
			if events != tc.wantEvent {
				t.Fatalf("ProcessEvent calls = %d, want %d", events, tc.wantEvent)
			}
		})
	}
}

func TestHandleEventAcceptsKernelTrackedExitMissingFromMirror(t *testing.T) {
	tests := []struct {
		name    string
		hasMark bool
		value   ProcessValue
	}{
		{
			name:    "marked",
			hasMark: true,
			value: ProcessValue{
				Tombstone:  true,
				HasMark:    true,
				Generation: 5,
				Mark:       200,
				Timestamp:  1,
			},
		},
		{
			name: "live no mark",
			value: ProcessValue{
				Tombstone:  true,
				HasMark:    false,
				Generation: 6,
				Timestamp:  1,
			},
		},
	}

	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := ProcessKey{Tgid: uint32(999980 + index), StartTime: uint64(3001 + index)}
			m := &marker{mirror: make(map[ProcessKey]ProcessValue)}

			m.handleEvent(markEvent{
				Type:    eventExit,
				Key:     key,
				HasMark: tc.hasMark,
				Value:   tc.value,
			})

			got, ok := m.mirror[key]
			if !ok {
				t.Fatalf("kernel-tracked process is missing from mirror")
			}
			if !got.Tombstone {
				t.Fatalf("Tombstone = false, want true")
			}
			if got.HasMark != tc.value.HasMark || got.Generation != tc.value.Generation || got.Mark != tc.value.Mark {
				t.Fatalf("mirror value = %+v, want kernel state from %+v", got, tc.value)
			}
			if got.Timestamp <= tc.value.Timestamp {
				t.Fatalf("Timestamp = %d, want greater than %d", got.Timestamp, tc.value.Timestamp)
			}
		})
	}
}

func TestHandleExecMergesNewerKernelDecisionOverStaleMirror(t *testing.T) {
	key := ProcessKey{Tgid: 999970, StartTime: 4001}
	m := &marker{
		mirror: map[ProcessKey]ProcessValue{
			key: {HasMark: true, Inheritance: true, Priority: 9, Generation: 2, Mark: 20, Timestamp: 100},
		},
		generation: 3,
		check: func(ProcessInfo) (int8, uint64, bool) {
			return 1, 30, true
		},
	}

	m.handleEvent(markEvent{
		Type:    eventExec,
		Key:     key,
		HasMark: true,
		Value: ProcessValue{
			HasMark:     true,
			Inheritance: true,
			Priority:    1,
			Generation:  3,
			Mark:        30,
			Timestamp:   200,
		},
	})

	got := m.mirror[key]
	if !got.HasMark || got.Generation != 3 || got.Mark != 30 {
		t.Fatalf("merged exec value = %+v, want generation 3 mark 30", got)
	}
}

func TestHandleExecAcceptsAuthoritativeKernelMiss(t *testing.T) {
	key := ProcessKey{Tgid: 999969, StartTime: 4002}
	m := &marker{
		mirror: map[ProcessKey]ProcessValue{
			key: {HasMark: true, Inheritance: false, Priority: 8, Generation: 2, Mark: 20, Timestamp: 100},
		},
		generation: 3,
		check:      func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false },
	}

	m.handleEvent(markEvent{
		Type: eventExec,
		Key:  key,
		Value: ProcessValue{
			HasMark:    false,
			Generation: 3,
			Timestamp:  200,
		},
	})

	got := m.mirror[key]
	if got.HasMark || got.Generation != 3 {
		t.Fatalf("merged exec value = %+v, want authoritative generation 3 miss", got)
	}
}

func TestHandleExecDoesNotReviveKernelTombstone(t *testing.T) {
	key := ProcessKey{Tgid: 999968, StartTime: 4003}
	checkCalls := 0
	logs := 0
	m := &marker{
		mirror:     make(map[ProcessKey]ProcessValue),
		generation: 4,
		check: func(ProcessInfo) (int8, uint64, bool) {
			checkCalls++
			return 1, 40, true
		},
		callbacks: Callbacks{Logf: func(string, ...any) { logs++ }},
	}

	tombstone := ProcessValue{Tombstone: true, HasMark: true, Generation: 3, Mark: 30, Timestamp: 200}
	m.handleEvent(markEvent{Type: eventExec, Key: key, Value: tombstone})

	if got := m.mirror[key]; got != tombstone {
		t.Fatalf("exec tombstone = %+v, want %+v", got, tombstone)
	}
	if checkCalls != 0 {
		t.Fatalf("checker calls = %d, want 0", checkCalls)
	}
	if logs != 1 {
		t.Fatalf("diagnostic logs = %d, want 1", logs)
	}
}

func TestUpdateHooksReplaysExistingLiveProcessUpdates(t *testing.T) {
	liveMarked := ProcessKey{Tgid: 101, StartTime: 1001}
	liveUnmarked := ProcessKey{Tgid: 102, StartTime: 1002}
	tombstone := ProcessKey{Tgid: 103, StartTime: 1003}
	m := &marker{
		mirror: map[ProcessKey]ProcessValue{
			liveMarked:   {HasMark: true},
			liveUnmarked: {HasMark: false},
			tombstone:    {Tombstone: true, HasMark: true},
		},
	}

	seen := make(map[ProcessKey]ProcessValue)
	m.updateHooks(Callbacks{
		ProcessUpdate: func(update ProcessUpdate) {
			seen[update.Key] = update.Value
		},
	})

	if len(seen) != 2 {
		t.Fatalf("replayed updates = %d, want 2", len(seen))
	}
	if _, ok := seen[liveMarked]; !ok {
		t.Fatalf("missing replay for live marked entry")
	}
	if _, ok := seen[liveUnmarked]; !ok {
		t.Fatalf("missing replay for live unmarked entry")
	}
	if _, ok := seen[tombstone]; ok {
		t.Fatalf("replayed tombstone entry")
	}
}

func TestForceProcessTraversalKeepsGeneration(t *testing.T) {
	checkCalls := 0
	d := &Daemon{
		marker: &marker{
			mirror:     make(map[ProcessKey]ProcessValue),
			check:      func(ProcessInfo) (int8, uint64, bool) { checkCalls++; return 0, 0, false },
			generation: 7,
		},
	}

	if err := d.ForceProcessTraversal(); err != nil {
		t.Fatalf("ForceProcessTraversal() error = %v", err)
	}
	if d.marker.generation != 7 {
		t.Fatalf("generation = %d, want 7", d.marker.generation)
	}
	if checkCalls == 0 {
		t.Fatalf("checker was not called")
	}
}

func TestForceBumpGenerationKeepsCheckerAndTraverses(t *testing.T) {
	checkCalls := 0
	d := &Daemon{
		marker: &marker{
			mirror:     make(map[ProcessKey]ProcessValue),
			check:      func(ProcessInfo) (int8, uint64, bool) { checkCalls++; return 0, 0, false },
			generation: 7,
		},
	}

	generation, err := d.ForceBumpGeneration()
	if err != nil {
		t.Fatalf("ForceBumpGeneration() error = %v", err)
	}
	if generation != 8 {
		t.Fatalf("returned generation = %d, want 8", generation)
	}
	if d.marker.generation != 8 {
		t.Fatalf("generation = %d, want 8", d.marker.generation)
	}
	if checkCalls == 0 {
		t.Fatalf("checker was not called")
	}
}

func TestSetCheckerReturnsResultingGeneration(t *testing.T) {
	checkCalls := 0
	d := &Daemon{
		marker: &marker{
			mirror:     make(map[ProcessKey]ProcessValue),
			check:      func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false },
			generation: 7,
		},
	}

	generation, err := d.SetChecker(func(ProcessInfo) (int8, uint64, bool) {
		checkCalls++
		return 0, 0, false
	})
	if err != nil {
		t.Fatalf("SetChecker() error = %v", err)
	}
	if generation != 8 {
		t.Fatalf("returned generation = %d, want 8", generation)
	}
	if d.marker.generation != 8 {
		t.Fatalf("generation = %d, want 8", d.marker.generation)
	}
	if checkCalls == 0 {
		t.Fatalf("new checker was not called")
	}
}

func TestSetProcessMarkWritesExplicitCurrentGenerationMark(t *testing.T) {
	key := ProcessKey{Tgid: 301, StartTime: 3001}
	d := &Daemon{
		marker: &marker{
			mirror:     make(map[ProcessKey]ProcessValue),
			generation: 9,
		},
	}

	var seen *ProcessUpdate
	d.marker.callbacks.ProcessUpdate = func(update ProcessUpdate) {
		seen = &update
	}

	d.SetProcessMark(key, 4, 1234)

	value, ok := d.marker.mirror[key]
	if !ok {
		t.Fatalf("missing explicit mark")
	}
	if value.Tombstone {
		t.Fatalf("Tombstone = true, want false")
	}
	if !value.HasMark {
		t.Fatalf("HasMark = false, want true")
	}
	if !value.Inheritance {
		t.Fatalf("Inheritance = false, want true for explicit mark")
	}
	if value.Priority != 4 {
		t.Fatalf("Priority = %d, want 4", value.Priority)
	}
	if value.Mark != 1234 {
		t.Fatalf("Mark = %d, want 1234", value.Mark)
	}
	if value.Generation != 9 {
		t.Fatalf("Generation = %d, want 9", value.Generation)
	}
	if value.Timestamp == 0 {
		t.Fatalf("Timestamp = 0, want current boot timestamp")
	}
	if seen == nil {
		t.Fatalf("missing ProcessUpdate")
	}
	if seen.Key != key || seen.Value != value {
		t.Fatalf("ProcessUpdate = %+v, want key=%+v value=%+v", *seen, key, value)
	}
}

func TestSetProcessMarkUsesProcessValueMergeRules(t *testing.T) {
	key := ProcessKey{Tgid: 302, StartTime: 3002}
	old := ProcessValue{
		HasMark:    true,
		Priority:   10,
		Generation: 9,
		Mark:       9000,
		Timestamp:  1,
	}
	d := &Daemon{
		marker: &marker{
			mirror: map[ProcessKey]ProcessValue{
				key: old,
			},
			generation: 9,
		},
	}

	updates := 0
	d.marker.callbacks.ProcessUpdate = func(ProcessUpdate) {
		updates++
	}

	d.SetProcessMark(key, 1, 1000)

	if got := d.marker.mirror[key]; got != old {
		t.Fatalf("mirror value = %+v, want existing higher-priority value %+v", got, old)
	}
	if updates != 0 {
		t.Fatalf("ProcessUpdate calls = %d, want 0 for unchanged merge winner", updates)
	}
}

func TestCurrentGeneration(t *testing.T) {
	d := &Daemon{
		marker: &marker{generation: 42},
	}

	if got := d.CurrentGeneration(); got != 42 {
		t.Fatalf("CurrentGeneration() = %d, want 42", got)
	}
}

func TestProcCommLinePreservesMeaningfulWhitespace(t *testing.T) {
	tests := map[string]string{
		"curl\n":     "curl",
		" curl \n":   " curl ",
		"line\n\n":   "line\n",
		"no-newline": "no-newline",
	}
	for input, want := range tests {
		if got := trimProcLine([]byte(input)); got != want {
			t.Errorf("trimProcLine(%q) = %q, want %q", input, got, want)
		}
	}

	path := "/proc/self/comm"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("read %s: %v", path, err)
	}
	want := strings.TrimSuffix(string(data), "\n")
	if got := readProcText(uint32(os.Getpid()), "comm"); got != want {
		t.Fatalf("readProcText(self, comm) = %q, want %q", got, want)
	}
}

func TestStopReplaysAllProcessUpdatesAsUnmarkedCopies(t *testing.T) {
	marked := ProcessKey{Tgid: 201, StartTime: 2001}
	unmarked := ProcessKey{Tgid: 202, StartTime: 2002}
	unmarkedTombstone := ProcessKey{Tgid: 203, StartTime: 2003}
	done := make(chan error, 1)
	done <- nil
	d := &Daemon{
		done: done,
		marker: &marker{
			mirror: map[ProcessKey]ProcessValue{
				marked:            {HasMark: true},
				unmarked:          {HasMark: false},
				unmarkedTombstone: {Tombstone: true, HasMark: false},
			},
			callbacks: Callbacks{
				ProcessUpdate: func(update ProcessUpdate) {},
			},
		},
	}

	seen := make(map[ProcessKey]ProcessValue)
	d.marker.callbacks.ProcessUpdate = func(update ProcessUpdate) {
		seen[update.Key] = update.Value
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("replayed updates = %d, want 3", len(seen))
	}
	if value, ok := seen[marked]; !ok {
		t.Fatalf("missing replay for marked entry")
	} else if value.HasMark {
		t.Fatalf("marked replay HasMark = true, want false")
	}
	if _, ok := seen[unmarked]; !ok {
		t.Fatalf("missing replay for unmarked live entry")
	}
	if _, ok := seen[unmarkedTombstone]; !ok {
		t.Fatalf("missing replay for unmarked tombstone entry")
	}
	if !d.marker.mirror[marked].HasMark {
		t.Fatalf("Stop mutated marked mirror entry")
	}
}
