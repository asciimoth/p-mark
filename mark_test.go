package pmark

import "testing"

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
