package pmark

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	// TaskCommLength is the fixed Linux task comm buffer size, including its
	// terminating NUL byte.
	TaskCommLength = 16

	// MaxKernelCommRules is the maximum number of exact rules in one policy
	// generation. The BPF map holds two complete generations during a switch.
	MaxKernelCommRules = 1024
)

// KernelPolicyMode describes how much of a userspace mark policy the exec BPF
// program can decide synchronously.
type KernelPolicyMode uint8

const (
	// KernelPolicyUserspaceOnly leaves exec decisions to CheckFunc.
	KernelPolicyUserspaceOnly KernelPolicyMode = iota

	// KernelPolicyPositiveOnly applies exact kernel matches immediately. A miss
	// preserves the current value because an unsupported userspace rule can
	// still match.
	KernelPolicyPositiveOnly

	// KernelPolicyAuthoritative applies exact matches and clears the process
	// mark on a miss before exec returns.
	KernelPolicyAuthoritative
)

func (mode KernelPolicyMode) String() string {
	switch mode {
	case KernelPolicyUserspaceOnly:
		return "userspace-only"
	case KernelPolicyPositiveOnly:
		return "positive-only"
	case KernelPolicyAuthoritative:
		return "authoritative"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(mode))
	}
}

// ExactCommRule is one byte-exact, case-sensitive Linux comm rule.
//
// Comm must not contain NUL and must fit in TASK_COMM_LEN-1 bytes. When two
// rules use the same Comm, the higher priority wins. The first rule wins a
// priority tie.
type ExactCommRule struct {
	Comm     string
	Priority int8
	Mark     uint64
}

// KernelPolicy is the exec policy installed in the BPF maps.
type KernelPolicy struct {
	Mode      KernelPolicyMode
	CommRules []ExactCommRule
}

// KernelPolicyStatus is a point-in-time description of the active policy.
type KernelPolicyStatus struct {
	Generation uint64
	Mode       KernelPolicyMode
	RuleCount  int
}

// ExactCommFromRegexp returns the exact comm represented by pattern.
//
// The accepted subset is deliberately narrow: a beginning-of-text anchor,
// zero or more case-sensitive literal runes, and an end-of-text anchor. The
// function returns supported=false for valid expressions outside this subset.
func ExactCommFromRegexp(pattern string) (comm string, supported bool, err error) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return "", false, err
	}
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return "", false, nil
	}
	if re.Sub[0].Op != syntax.OpBeginText || re.Sub[len(re.Sub)-1].Op != syntax.OpEndText {
		return "", false, nil
	}

	var literal strings.Builder
	for _, part := range re.Sub[1 : len(re.Sub)-1] {
		if part.Op != syntax.OpLiteral || part.Flags&syntax.FoldCase != 0 {
			return "", false, nil
		}
		literal.WriteString(string(part.Rune))
	}

	comm = literal.String()
	if err := validateExactComm(comm); err != nil {
		return "", false, nil
	}
	return comm, true, nil
}

func validateAndNormalizeKernelPolicy(policy KernelPolicy) (KernelPolicy, error) {
	if policy.Mode > KernelPolicyAuthoritative {
		return KernelPolicy{}, fmt.Errorf("invalid kernel policy mode %d", policy.Mode)
	}
	if policy.Mode == KernelPolicyUserspaceOnly && len(policy.CommRules) != 0 {
		return KernelPolicy{}, fmt.Errorf("userspace-only policy cannot contain exact comm rules")
	}
	if len(policy.CommRules) > MaxKernelCommRules {
		return KernelPolicy{}, fmt.Errorf("kernel policy has %d comm rules; maximum is %d", len(policy.CommRules), MaxKernelCommRules)
	}

	normalized := KernelPolicy{Mode: policy.Mode}
	indices := make(map[string]int, len(policy.CommRules))
	for index, rule := range policy.CommRules {
		if err := validateExactComm(rule.Comm); err != nil {
			return KernelPolicy{}, fmt.Errorf("comm rule %d: %w", index, err)
		}
		if existingIndex, ok := indices[rule.Comm]; ok {
			if rule.Priority > normalized.CommRules[existingIndex].Priority {
				normalized.CommRules[existingIndex] = rule
			}
			continue
		}
		indices[rule.Comm] = len(normalized.CommRules)
		normalized.CommRules = append(normalized.CommRules, rule)
	}
	return normalized, nil
}

func validateExactComm(comm string) error {
	if strings.IndexByte(comm, 0) >= 0 {
		return fmt.Errorf("comm contains NUL")
	}
	if len(comm) > TaskCommLength-1 {
		return fmt.Errorf("comm is %d bytes; maximum is %d", len(comm), TaskCommLength-1)
	}
	return nil
}

func exactCommCheck(rules []ExactCommRule) CheckFunc {
	rules = append([]ExactCommRule(nil), rules...)
	return func(info ProcessInfo) (int8, uint64, bool) {
		matched := false
		var priority int8
		var mark uint64
		for _, rule := range rules {
			if info.Comm != rule.Comm {
				continue
			}
			if !matched || rule.Priority > priority {
				matched = true
				priority = rule.Priority
				mark = rule.Mark
			}
		}
		return priority, mark, matched
	}
}

type bpfMapMutator interface {
	Put(key, value interface{}) error
	Delete(key interface{}) error
}

func nextPolicyGeneration(current uint64) (uint64, error) {
	if current == ^uint64(0) {
		return 0, fmt.Errorf("kernel policy generation is exhausted; restart the daemon")
	}
	return current + 1, nil
}

func makeCommRuleKey(generation uint64, comm string) (markCommRuleKey, error) {
	if err := validateExactComm(comm); err != nil {
		return markCommRuleKey{}, err
	}
	key := markCommRuleKey{Generation: generation}
	for index, value := range []byte(comm) {
		key.Comm[index] = int8(value)
	}
	return key, nil
}

func (m *marker) setKernelPolicy(policy KernelPolicy, check CheckFunc) (uint64, error) {
	normalized, err := validateAndNormalizeKernelPolicy(policy)
	if err != nil {
		return m.currentGeneration(), err
	}
	if check == nil {
		check = exactCommCheck(normalized.CommRules)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setKernelPolicyLocked(normalized, check)
}

func (m *marker) setKernelPolicyLocked(policy KernelPolicy, check CheckFunc) (uint64, error) {
	_, err := listProcesses()
	if err != nil {
		return m.generation, fmt.Errorf("list processes before kernel policy switch: %w", err)
	}
	m.cleanupInactiveCommRulesLocked(m.generation)

	generationCursor := m.policyGeneration
	if generationCursor < m.generation {
		generationCursor = m.generation
	}
	nextGeneration, err := nextPolicyGeneration(generationCursor)
	if err != nil {
		return m.generation, err
	}
	// Reserve the generation before the first map write. A failed transaction
	// never reuses it because rollback deletion can also fail.
	m.policyGeneration = nextGeneration

	keys := make([]markCommRuleKey, 0, len(policy.CommRules))
	for _, rule := range policy.CommRules {
		key, err := makeCommRuleKey(nextGeneration, rule.Comm)
		if err != nil {
			return m.generation, err
		}
		if m.commRules != nil {
			value := markCommRuleValue{Priority: rule.Priority, Mark: rule.Mark}
			if err := m.commRules.Put(key, value); err != nil {
				m.rememberUndeletedCommRules(nextGeneration, m.deleteCommRuleKeys(keys))
				return m.generation, fmt.Errorf("populate kernel comm rule %q: %w", rule.Comm, err)
			}
		}
		keys = append(keys, key)
	}

	oldCheck := m.check
	oldGeneration := m.generation
	oldPolicy := m.kernelPolicy
	m.check = check
	m.generation = nextGeneration
	m.kernelPolicy = policy

	if m.activePolicy != nil {
		state := markKernelPolicyState{Generation: nextGeneration, Mode: uint8(policy.Mode)}
		if err := m.activePolicy.Put(uint32(0), state); err != nil {
			m.check = oldCheck
			m.generation = oldGeneration
			m.kernelPolicy = oldPolicy
			m.rememberUndeletedCommRules(nextGeneration, m.deleteCommRuleKeys(keys))
			return oldGeneration, fmt.Errorf("activate kernel policy generation %d: %w", nextGeneration, err)
		}
	}

	if m.installedCommRules == nil {
		m.installedCommRules = make(map[uint64][]markCommRuleKey)
	}
	m.installedCommRules[nextGeneration] = keys

	if err := m.traverseProcessTreeLocked(); err != nil {
		m.logf("process traversal after kernel policy switch: %v", err)
	}
	m.cleanupInactiveCommRulesLocked(nextGeneration)
	m.logf("kernel policy active: mode=%s generation=%d comm_rules=%d", policy.Mode, nextGeneration, len(policy.CommRules))
	return nextGeneration, nil
}

func (m *marker) deleteCommRuleKeys(keys []markCommRuleKey) []markCommRuleKey {
	if m.commRules == nil {
		return nil
	}
	remaining := make([]markCommRuleKey, 0)
	for _, key := range keys {
		if err := m.commRules.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			remaining = append(remaining, key)
			m.logf("rollback kernel comm rule generation=%d comm=%q: %v", key.Generation, int8String(key.Comm), err)
		}
	}
	return remaining
}

func (m *marker) rememberUndeletedCommRules(generation uint64, keys []markCommRuleKey) {
	if len(keys) == 0 {
		return
	}
	if m.installedCommRules == nil {
		m.installedCommRules = make(map[uint64][]markCommRuleKey)
	}
	m.installedCommRules[generation] = keys
}

func (m *marker) cleanupInactiveCommRulesLocked(activeGeneration uint64) {
	if m.commRules == nil {
		for generation := range m.installedCommRules {
			if generation != activeGeneration {
				delete(m.installedCommRules, generation)
			}
		}
		return
	}

	for generation, keys := range m.installedCommRules {
		if generation == activeGeneration {
			continue
		}
		remaining := keys[:0]
		for _, key := range keys {
			if err := m.commRules.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				remaining = append(remaining, key)
				m.logf("delete inactive kernel comm rule generation=%d comm=%q: %v", generation, int8String(key.Comm), err)
			}
		}
		if len(remaining) == 0 {
			delete(m.installedCommRules, generation)
		} else {
			m.installedCommRules[generation] = remaining
		}
	}
}
