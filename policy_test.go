package pmark

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestKernelPolicyModeString(t *testing.T) {
	tests := []struct {
		mode KernelPolicyMode
		want string
	}{
		{KernelPolicyUserspaceOnly, "userspace-only"},
		{KernelPolicyPositiveOnly, "positive-only"},
		{KernelPolicyAuthoritative, "authoritative"},
		{KernelPolicyMode(99), "unknown(99)"},
	}
	for _, tc := range tests {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("KernelPolicyMode(%d).String() = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestExactCommFromRegexp(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		want      string
		supported bool
		wantErr   bool
	}{
		{"anchored literal", `^curl$`, "curl", true, false},
		{"text anchors", `\Acurl\z`, "curl", true, false},
		{"escaped literals", `^a\.b\$\\c$`, `a.b$\c`, true, false},
		{"unicode within byte limit", `^猫$`, "猫", true, false},
		{"empty literal", `^$`, "", true, false},
		{"unanchored", `curl`, "", false, false},
		{"missing end anchor", `^curl`, "", false, false},
		{"missing start anchor", `curl$`, "", false, false},
		{"case folded", `(?i)^curl$`, "", false, false},
		{"multiline anchors", `(?m)^curl$`, "", false, false},
		{"character class", `^[a-z]+$`, "", false, false},
		{"repetition", `^curl+$`, "", false, false},
		{"capture", `^(curl)$`, "", false, false},
		{"alternation", `^(curl|wget)$`, "", false, false},
		{"too long", `^1234567890123456$`, "", false, false},
		{"embedded NUL", "^a\x00b$", "", false, false},
		{"invalid", `[`, "", false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, supported, err := ExactCommFromRegexp(tc.pattern)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ExactCommFromRegexp(%q) error = %v, wantErr %v", tc.pattern, err, tc.wantErr)
			}
			if got != tc.want || supported != tc.supported {
				t.Fatalf("ExactCommFromRegexp(%q) = %q, %v; want %q, %v", tc.pattern, got, supported, tc.want, tc.supported)
			}
		})
	}
}

func TestExactCommRegexpDifferential(t *testing.T) {
	patterns := []string{`^curl$`, `\Afoo\.bar\z`, `^猫$`, `^$`}
	inputs := []string{"", "curl", "curl\n", "xcurly", "foo.bar", "fooXbar", "猫", "猫猫"}
	for _, pattern := range patterns {
		comm, supported, err := ExactCommFromRegexp(pattern)
		if err != nil || !supported {
			t.Fatalf("ExactCommFromRegexp(%q) = %q, %v, %v; want supported", pattern, comm, supported, err)
		}
		re := regexp.MustCompile(pattern)
		for _, input := range inputs {
			if got, want := input == comm, re.MatchString(input); got != want {
				t.Errorf("pattern %q input %q: exact match = %v, regexp match = %v", pattern, input, got, want)
			}
		}
	}
}

func TestValidateAndNormalizeKernelPolicy(t *testing.T) {
	policy, err := validateAndNormalizeKernelPolicy(KernelPolicy{
		Mode: KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{
			{Comm: "curl", Priority: 1, Mark: 10},
			{Comm: "curl", Priority: 3, Mark: 30},
			{Comm: "curl", Priority: 3, Mark: 31},
			{Comm: "wget", Priority: -1, Mark: 40},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []ExactCommRule{
		{Comm: "curl", Priority: 3, Mark: 30},
		{Comm: "wget", Priority: -1, Mark: 40},
	}
	if !reflect.DeepEqual(policy.CommRules, want) {
		t.Fatalf("normalized rules = %+v, want %+v", policy.CommRules, want)
	}

	invalid := []KernelPolicy{
		{Mode: KernelPolicyMode(3)},
		{Mode: KernelPolicyUserspaceOnly, CommRules: []ExactCommRule{{Comm: "curl"}}},
		{Mode: KernelPolicyAuthoritative, CommRules: []ExactCommRule{{Comm: "a\x00b"}}},
		{Mode: KernelPolicyAuthoritative, CommRules: []ExactCommRule{{Comm: "1234567890123456"}}},
	}
	tooMany := KernelPolicy{Mode: KernelPolicyAuthoritative}
	for index := 0; index <= MaxKernelCommRules; index++ {
		tooMany.CommRules = append(tooMany.CommRules, ExactCommRule{Comm: fmt.Sprintf("r%04d", index)})
	}
	invalid = append(invalid, tooMany)
	for index, item := range invalid {
		if _, err := validateAndNormalizeKernelPolicy(item); err == nil {
			t.Errorf("invalid policy %d was accepted", index)
		}
	}
}

func TestExactCommCheckUsesPriorityAndStableTies(t *testing.T) {
	check := exactCommCheck([]ExactCommRule{
		{Comm: "curl", Priority: 1, Mark: 10},
		{Comm: "curl", Priority: 4, Mark: 40},
		{Comm: "curl", Priority: 4, Mark: 41},
	})
	priority, mark, ok := check(ProcessInfo{Comm: "curl"})
	if !ok || priority != 4 || mark != 40 {
		t.Fatalf("exact check = %d, %d, %v; want 4, 40, true", priority, mark, ok)
	}
	if _, _, ok := check(ProcessInfo{Comm: "wget"}); ok {
		t.Fatal("exact check matched an unrelated comm")
	}
}

func TestMakeCommRuleKeyZeroFillsAndUsesBytes(t *testing.T) {
	key, err := makeCommRuleKey(9, "猫")
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation != 9 {
		t.Fatalf("generation = %d, want 9", key.Generation)
	}
	wantPrefix := []byte("猫")
	for index, want := range wantPrefix {
		if got := byte(key.Comm[index]); got != want {
			t.Fatalf("comm byte %d = %#x, want %#x", index, got, want)
		}
	}
	for index := len(wantPrefix); index < len(key.Comm); index++ {
		if key.Comm[index] != 0 {
			t.Fatalf("comm byte %d = %#x, want zero fill", index, byte(key.Comm[index]))
		}
	}
}

func TestNextPolicyGenerationRejectsWraparound(t *testing.T) {
	if got, err := nextPolicyGeneration(7); err != nil || got != 8 {
		t.Fatalf("nextPolicyGeneration(7) = %d, want 8", got)
	}
	if _, err := nextPolicyGeneration(^uint64(0)); err == nil {
		t.Fatal("nextPolicyGeneration(max) error = nil, want exhaustion error")
	}
}

var errFakeMapPut = errors.New("fake map put failure")
var errFakeMapDelete = errors.New("fake map delete failure")

type fakeMapOperation struct {
	mapName string
	kind    string
	key     interface{}
}

type fakePolicyMap struct {
	name       string
	operations *[]fakeMapOperation
	values     map[interface{}]interface{}
	putCount   int
	failPutAt  int
	failDelete bool
}

func newFakePolicyMap(name string, operations *[]fakeMapOperation) *fakePolicyMap {
	return &fakePolicyMap{name: name, operations: operations, values: make(map[interface{}]interface{})}
}

func (m *fakePolicyMap) Put(key, value interface{}) error {
	m.putCount++
	*m.operations = append(*m.operations, fakeMapOperation{mapName: m.name, kind: "put", key: key})
	if m.failPutAt != 0 && m.putCount == m.failPutAt {
		return errFakeMapPut
	}
	m.values[key] = value
	return nil
}

func (m *fakePolicyMap) Delete(key interface{}) error {
	*m.operations = append(*m.operations, fakeMapOperation{mapName: m.name, kind: "delete", key: key})
	if m.failDelete {
		return errFakeMapDelete
	}
	delete(m.values, key)
	return nil
}

func TestSetKernelPolicyRollsBackRulePopulationFailure(t *testing.T) {
	operations := []fakeMapOperation{}
	rulesMap := newFakePolicyMap("rules", &operations)
	rulesMap.failPutAt = 2
	stateMap := newFakePolicyMap("state", &operations)
	oldCheckCalls := 0
	m := &marker{
		commRules:          rulesMap,
		activePolicy:       stateMap,
		mirror:             make(map[ProcessKey]ProcessValue),
		check:              func(ProcessInfo) (int8, uint64, bool) { oldCheckCalls++; return 0, 0, false },
		generation:         7,
		kernelPolicy:       KernelPolicy{Mode: KernelPolicyUserspaceOnly},
		installedCommRules: make(map[uint64][]markCommRuleKey),
	}

	_, err := m.setKernelPolicy(KernelPolicy{
		Mode: KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{
			{Comm: "curl", Mark: 1},
			{Comm: "wget", Mark: 2},
		},
	}, nil)
	if !errors.Is(err, errFakeMapPut) {
		t.Fatalf("setKernelPolicy() error = %v, want fake put failure", err)
	}
	if m.generation != 7 || m.kernelPolicy.Mode != KernelPolicyUserspaceOnly {
		t.Fatalf("active policy changed after population failure: generation=%d policy=%+v", m.generation, m.kernelPolicy)
	}
	if len(rulesMap.values) != 0 {
		t.Fatalf("partial rules remain after failure: %+v", rulesMap.values)
	}
	if stateMap.putCount != 0 {
		t.Fatalf("active state writes = %d, want 0", stateMap.putCount)
	}
	if _, _, _ = m.check(ProcessInfo{}); oldCheckCalls != 1 {
		t.Fatal("old checker was not restored")
	}
}

func TestSetKernelPolicyRollsBackActiveStateFailure(t *testing.T) {
	operations := []fakeMapOperation{}
	rulesMap := newFakePolicyMap("rules", &operations)
	stateMap := newFakePolicyMap("state", &operations)
	stateMap.failPutAt = 1
	oldCheckCalls := 0
	m := &marker{
		commRules:          rulesMap,
		activePolicy:       stateMap,
		mirror:             make(map[ProcessKey]ProcessValue),
		check:              func(ProcessInfo) (int8, uint64, bool) { oldCheckCalls++; return 0, 0, false },
		generation:         10,
		kernelPolicy:       KernelPolicy{Mode: KernelPolicyUserspaceOnly},
		installedCommRules: make(map[uint64][]markCommRuleKey),
	}

	_, err := m.setKernelPolicy(KernelPolicy{
		Mode:      KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{{Comm: "curl", Mark: 1}},
	}, nil)
	if !errors.Is(err, errFakeMapPut) {
		t.Fatalf("setKernelPolicy() error = %v, want fake put failure", err)
	}
	if m.generation != 10 || m.kernelPolicy.Mode != KernelPolicyUserspaceOnly {
		t.Fatalf("active policy changed after state failure: generation=%d policy=%+v", m.generation, m.kernelPolicy)
	}
	if len(rulesMap.values) != 0 {
		t.Fatalf("new rules remain after state failure: %+v", rulesMap.values)
	}
	if _, _, _ = m.check(ProcessInfo{}); oldCheckCalls != 1 {
		t.Fatal("old checker was not restored")
	}
}

func TestSetKernelPolicyDoesNotReuseContaminatedFailedGeneration(t *testing.T) {
	operations := []fakeMapOperation{}
	rulesMap := newFakePolicyMap("rules", &operations)
	rulesMap.failPutAt = 2
	rulesMap.failDelete = true
	stateMap := newFakePolicyMap("state", &operations)
	m := &marker{
		commRules:          rulesMap,
		activePolicy:       stateMap,
		mirror:             make(map[ProcessKey]ProcessValue),
		check:              func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false },
		generation:         7,
		policyGeneration:   7,
		kernelPolicy:       KernelPolicy{Mode: KernelPolicyUserspaceOnly},
		installedCommRules: make(map[uint64][]markCommRuleKey),
	}

	_, err := m.setKernelPolicy(KernelPolicy{
		Mode: KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{
			{Comm: "stale", Mark: 1},
			{Comm: "fails", Mark: 2},
		},
	}, nil)
	if !errors.Is(err, errFakeMapPut) {
		t.Fatalf("first setKernelPolicy() error = %v, want fake put failure", err)
	}
	if m.policyGeneration != 8 || len(m.installedCommRules[8]) != 1 {
		t.Fatalf("failed generation state = cursor %d keys %+v, want cursor 8 with one stale key", m.policyGeneration, m.installedCommRules)
	}

	rulesMap.failPutAt = 0
	rulesMap.failDelete = false
	generation, err := m.setKernelPolicy(KernelPolicy{
		Mode:      KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{{Comm: "fresh", Mark: 3}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if generation != 9 {
		t.Fatalf("successful generation = %d, want 9", generation)
	}
	for key := range rulesMap.values {
		ruleKey := key.(markCommRuleKey)
		if ruleKey.Generation != 9 || int8String(ruleKey.Comm) != "fresh" {
			t.Fatalf("stale failed-generation rule became active: %#v", ruleKey)
		}
	}
}

func TestSetKernelPolicySwitchesThenCleansInactiveGeneration(t *testing.T) {
	operations := []fakeMapOperation{}
	rulesMap := newFakePolicyMap("rules", &operations)
	stateMap := newFakePolicyMap("state", &operations)
	m := &marker{
		commRules:          rulesMap,
		activePolicy:       stateMap,
		mirror:             make(map[ProcessKey]ProcessValue),
		check:              func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false },
		generation:         1,
		kernelPolicy:       KernelPolicy{Mode: KernelPolicyUserspaceOnly},
		installedCommRules: make(map[uint64][]markCommRuleKey),
	}

	first, err := m.setKernelPolicy(KernelPolicy{
		Mode:      KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{{Comm: "curl", Priority: 2, Mark: 10}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.setKernelPolicy(KernelPolicy{
		Mode:      KernelPolicyAuthoritative,
		CommRules: []ExactCommRule{{Comm: "wget", Priority: 3, Mark: 20}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != 2 || second != 3 {
		t.Fatalf("generations = %d, %d; want 2, 3", first, second)
	}
	state, ok := stateMap.values[uint32(0)].(markKernelPolicyState)
	if !ok || state.Generation != second || state.Mode != uint8(KernelPolicyAuthoritative) {
		t.Fatalf("active state = %+v, %v; want generation %d authoritative", state, ok, second)
	}
	if _, ok := m.installedCommRules[first]; ok {
		t.Fatalf("inactive generation %d remains tracked", first)
	}
	if len(m.installedCommRules[second]) != 1 {
		t.Fatalf("active generation keys = %d, want 1", len(m.installedCommRules[second]))
	}

	lastStatePut := -1
	lastRulePut := -1
	firstDelete := -1
	for index, operation := range operations {
		if operation.mapName == "state" && operation.kind == "put" {
			lastStatePut = index
		}
		if operation.mapName == "rules" && operation.kind == "put" {
			lastRulePut = index
		}
		if operation.mapName == "rules" && operation.kind == "delete" && firstDelete < 0 {
			firstDelete = index
		}
	}
	if lastRulePut < 0 || lastStatePut < 0 || lastRulePut > lastStatePut {
		t.Fatalf("operation order does not populate rules before the state switch: %+v", operations)
	}
	if firstDelete < 0 || firstDelete < lastStatePut {
		t.Fatalf("operation order does not switch state before cleanup: %+v", operations)
	}

	for key := range rulesMap.values {
		ruleKey, ok := key.(markCommRuleKey)
		if !ok || ruleKey.Generation != second || int8String(ruleKey.Comm) != "wget" {
			t.Fatalf("unexpected remaining rule key: %#v", key)
		}
	}
}

func TestSetCheckerSwitchesKernelPolicyToUserspaceOnly(t *testing.T) {
	operations := []fakeMapOperation{}
	rulesMap := newFakePolicyMap("rules", &operations)
	stateMap := newFakePolicyMap("state", &operations)
	oldKey, err := makeCommRuleKey(5, "curl")
	if err != nil {
		t.Fatal(err)
	}
	rulesMap.values[oldKey] = markCommRuleValue{Mark: 10}
	m := &marker{
		commRules:    rulesMap,
		activePolicy: stateMap,
		mirror:       make(map[ProcessKey]ProcessValue),
		check:        exactCommCheck([]ExactCommRule{{Comm: "curl", Mark: 10}}),
		generation:   5,
		kernelPolicy: KernelPolicy{
			Mode:      KernelPolicyAuthoritative,
			CommRules: []ExactCommRule{{Comm: "curl", Mark: 10}},
		},
		installedCommRules: map[uint64][]markCommRuleKey{5: {oldKey}},
	}
	d := &Daemon{marker: m}

	generation, err := d.SetChecker(func(ProcessInfo) (int8, uint64, bool) { return 0, 0, false })
	if err != nil {
		t.Fatal(err)
	}
	if generation != 6 {
		t.Fatalf("generation = %d, want 6", generation)
	}
	status := d.KernelPolicyState()
	if status.Mode != KernelPolicyUserspaceOnly || status.RuleCount != 0 || status.Generation != 6 {
		t.Fatalf("kernel policy state = %+v, want userspace-only generation 6", status)
	}
	state := stateMap.values[uint32(0)].(markKernelPolicyState)
	if state.Mode != uint8(KernelPolicyUserspaceOnly) || state.Generation != 6 {
		t.Fatalf("BPF policy state = %+v, want userspace-only generation 6", state)
	}
	if len(rulesMap.values) != 0 {
		t.Fatalf("inactive exact rules remain after SetChecker: %+v", rulesMap.values)
	}
}

func TestKernelPolicyValidationLeavesGenerationUnchanged(t *testing.T) {
	m := &marker{generation: 12}
	_, err := m.setKernelPolicy(KernelPolicy{
		Mode:      KernelPolicyUserspaceOnly,
		CommRules: []ExactCommRule{{Comm: "curl"}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "userspace-only") {
		t.Fatalf("setKernelPolicy() error = %v, want userspace-only validation error", err)
	}
	if m.generation != 12 {
		t.Fatalf("generation = %d, want 12", m.generation)
	}
}
