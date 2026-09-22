package main

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/asciimoth/p-mark"
)

func TestDefaultCheckMatchesAnyRule(t *testing.T) {
	check, err := defaultCheck(defaultCheckRules{
		RuleComm: `^firefox$`,
		RuleCmd:  `^/usr/bin/chromium(\s|$)`,
		RuleExe:  `(^|/)curl$`,
		RulePPID: `123,456`,
	}, 7, 99)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		info core.ProcessInfo
		want bool
	}{
		{
			name: "comm",
			info: core.ProcessInfo{Comm: "firefox"},
			want: true,
		},
		{
			name: "cmd",
			info: core.ProcessInfo{Cmdline: "/usr/bin/chromium --type=zygote"},
			want: true,
		},
		{
			name: "exe",
			info: core.ProcessInfo{Exe: "/usr/bin/curl"},
			want: true,
		},
		{
			name: "exe basename",
			info: core.ProcessInfo{Exe: "curl"},
			want: true,
		},
		{
			name: "ppid",
			info: core.ProcessInfo{PPID: 456},
			want: true,
		},
		{
			name: "none",
			info: core.ProcessInfo{PPID: 457, Comm: "bash", Cmdline: "/usr/bin/bash", Exe: "/usr/bin/bash"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priority, mark, ok := check(tt.info)
			if ok != tt.want {
				t.Fatalf("match = %v, want %v", ok, tt.want)
			}
			if tt.want && (priority != 7 || mark != 99) {
				t.Fatalf("priority, mark = %d, %d; want 7, 99", priority, mark)
			}
		})
	}
}

func TestDefaultCheckRejectsInvalidRules(t *testing.T) {
	if _, err := defaultCheck(defaultCheckRules{RuleComm: `[`}, 0, 0); err == nil {
		t.Fatal("expected invalid regexp error")
	}
	if _, err := defaultCheck(defaultCheckRules{RulePPID: `abc`}, 0, 0); err == nil {
		t.Fatal("expected invalid ppid error")
	}
}

func TestCompileDefaultKernelPolicyModes(t *testing.T) {
	tests := []struct {
		name         string
		rules        defaultCheckRules
		wantMode     core.KernelPolicyMode
		wantRules    []core.ExactCommRule
		wantPromoted int
		wantFallback int
	}{
		{
			name:         "anchored comm is authoritative",
			rules:        defaultCheckRules{RuleComm: `^curl$`},
			wantMode:     core.KernelPolicyAuthoritative,
			wantRules:    []core.ExactCommRule{{Comm: "curl", Priority: 7, Mark: 99}},
			wantPromoted: 1,
		},
		{
			name:         "empty policy is authoritative",
			wantMode:     core.KernelPolicyAuthoritative,
			wantRules:    []core.ExactCommRule{},
			wantPromoted: 0,
		},
		{
			name:         "mixed comm is positive only",
			rules:        defaultCheckRules{RuleComm: `^curl$,fire.*`},
			wantMode:     core.KernelPolicyPositiveOnly,
			wantRules:    []core.ExactCommRule{{Comm: "curl", Priority: 7, Mark: 99}},
			wantPromoted: 1,
			wantFallback: 1,
		},
		{
			name:         "other mark rule makes exact comm positive only",
			rules:        defaultCheckRules{RuleComm: `^curl$`, RuleExe: `curl$`},
			wantMode:     core.KernelPolicyPositiveOnly,
			wantRules:    []core.ExactCommRule{{Comm: "curl", Priority: 7, Mark: 99}},
			wantPromoted: 1,
			wantFallback: 1,
		},
		{
			name:         "unsupported policy is userspace only",
			rules:        defaultCheckRules{RuleComm: `curl`},
			wantMode:     core.KernelPolicyUserspaceOnly,
			wantRules:    []core.ExactCommRule{},
			wantFallback: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compileDefaultKernelPolicy(tc.rules, 7, 99)
			if err != nil {
				t.Fatal(err)
			}
			if got.Policy.Mode != tc.wantMode {
				t.Errorf("mode = %s, want %s", got.Policy.Mode, tc.wantMode)
			}
			if len(got.Policy.CommRules) != len(tc.wantRules) {
				t.Fatalf("rules = %+v, want %+v", got.Policy.CommRules, tc.wantRules)
			}
			for index := range tc.wantRules {
				if got.Policy.CommRules[index] != tc.wantRules[index] {
					t.Errorf("rule %d = %+v, want %+v", index, got.Policy.CommRules[index], tc.wantRules[index])
				}
			}
			if len(got.Promoted) != tc.wantPromoted || len(got.Fallback) != tc.wantFallback {
				t.Errorf("promoted/fallback = %v/%v, want counts %d/%d", got.Promoted, got.Fallback, tc.wantPromoted, tc.wantFallback)
			}
		})
	}
}

func TestCompileDefaultKernelPolicyKeepsUserspaceSemantics(t *testing.T) {
	compiled, err := compileDefaultKernelPolicy(defaultCheckRules{
		RuleComm: `^curl$,fire.*`,
		RuleCmd:  `--proxy`,
	}, -3, 123)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range []core.ProcessInfo{
		{Comm: "curl"},
		{Comm: "firefox"},
		{Cmdline: "tool --proxy value"},
	} {
		priority, mark, ok := compiled.Check(info)
		if !ok || priority != -3 || mark != 123 {
			t.Errorf("check(%+v) = %d, %d, %v; want -3, 123, true", info, priority, mark, ok)
		}
	}
	if _, _, ok := compiled.Check(core.ProcessInfo{Comm: "bash"}); ok {
		t.Fatal("compiled check matched unrelated process")
	}
}

func TestCompileDefaultKernelPolicyRejectsPromotedRuleOverflow(t *testing.T) {
	patterns := make([]string, 0, core.MaxKernelCommRules+1)
	for index := 0; index <= core.MaxKernelCommRules; index++ {
		patterns = append(patterns, fmt.Sprintf("^r%04d$", index))
	}
	_, err := compileDefaultKernelPolicy(defaultCheckRules{RuleComm: strings.Join(patterns, ",")}, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("compileDefaultKernelPolicy() error = %v, want rule limit error", err)
	}
}

func TestParseDefaultCheckUpdateForm(t *testing.T) {
	req := httptest.NewRequest("POST", "/rules", strings.NewReader("rule_comm=firefox&rule_cmd=chromium&rule_exe=curl&rule_ppid=123%2C456&mark_priority=-2&mark_value=42"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	update, err := parseDefaultCheckUpdate(req, 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	if update.Rules.RuleComm != "firefox" || update.Rules.RuleCmd != "chromium" || update.Rules.RuleExe != "curl" || update.Rules.RulePPID != "123,456" {
		t.Fatalf("rules = %+v", update.Rules)
	}
	if update.MarkPriority != -2 || update.MarkValue != 42 {
		t.Fatalf("mark priority/value = %d/%d", update.MarkPriority, update.MarkValue)
	}
}

func TestParseDefaultCheckUpdateJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(`{"rule_comm":" firefox ","rule_cmd":"chromium","rule_exe":"curl","rule_ppid":"123","mark_priority":3,"mark_value":44}`))
	req.Header.Set("Content-Type", "application/json")

	update, err := parseDefaultCheckUpdate(req, 1, 2)
	if err != nil {
		t.Fatal(err)
	}

	if update.Rules.RuleComm != "firefox" || update.Rules.RuleCmd != "chromium" || update.Rules.RuleExe != "curl" || update.Rules.RulePPID != "123" {
		t.Fatalf("rules = %+v", update.Rules)
	}
	if update.MarkPriority != 3 || update.MarkValue != 44 {
		t.Fatalf("mark priority/value = %d/%d", update.MarkPriority, update.MarkValue)
	}
}

func TestParseMultiRuleCLI(t *testing.T) {
	rules, err := parseMultiRuleCLI("comm=firefox&cmd=chromium&exe=curl&ppid=123")
	if err != nil {
		t.Fatal(err)
	}
	if rules.RuleComm != "firefox" || rules.RuleCmd != "chromium" || rules.RuleExe != "curl" || rules.RulePPID != "123" {
		t.Fatalf("rules = %+v", rules)
	}

	rules, err = parseMultiRuleCLI("firefox")
	if err != nil {
		t.Fatal(err)
	}
	if rules.RuleComm != "firefox" {
		t.Fatalf("bare rule comm = %q", rules.RuleComm)
	}
}

func TestParseMultiRuleUpdateForm(t *testing.T) {
	req := httptest.NewRequest("POST", "/multirules", strings.NewReader("rule_comm=firefox&rule_cmd=chromium&rule_exe=curl&rule_ppid=123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	update, err := parseMultiRuleUpdate(req)
	if err != nil {
		t.Fatal(err)
	}
	if update.Rules.RuleComm != "firefox" || update.Rules.RuleCmd != "chromium" || update.Rules.RuleExe != "curl" || update.Rules.RulePPID != "123" {
		t.Fatalf("rules = %+v", update.Rules)
	}
}

func TestParseMultiRuleUpdateJSONAliases(t *testing.T) {
	req := httptest.NewRequest("POST", "/multirules", strings.NewReader(`{"comm":"firefox","cmd":"chromium","exe":"curl","ppid":"123"}`))
	req.Header.Set("Content-Type", "application/json")

	update, err := parseMultiRuleUpdate(req)
	if err != nil {
		t.Fatal(err)
	}
	if update.Rules.RuleComm != "firefox" || update.Rules.RuleCmd != "chromium" || update.Rules.RuleExe != "curl" || update.Rules.RulePPID != "123" {
		t.Fatalf("rules = %+v", update.Rules)
	}
}

func TestMultiRuleManagerRegisterAndList(t *testing.T) {
	manager := newMultiRuleManager()
	rule, err := manager.Register(defaultCheckRules{RuleComm: "^firefox$"})
	if err != nil {
		t.Fatal(err)
	}
	manager.Tracker().ApplyProcess(core.ProcessInfo{
		Key:  core.ProcessKey{Tgid: 10, StartTime: 20},
		Comm: "firefox",
	})

	snapshot := manager.Snapshot()
	if got := snapshot[core.ProcessKey{Tgid: 10, StartTime: 20}]; len(got) != 1 || got[0] != rule.ID {
		t.Fatalf("matched rules = %v, want [%d]", got, rule.ID)
	}
	if list := manager.List(); len(list) != 1 || list[0].ID != rule.ID {
		t.Fatalf("list = %+v", list)
	}
	if !manager.Unregister(rule.ID) {
		t.Fatal("expected unregister to succeed")
	}
	if got := manager.Snapshot()[core.ProcessKey{Tgid: 10, StartTime: 20}]; len(got) != 0 {
		t.Fatalf("matched rules after unregister = %v", got)
	}
}
