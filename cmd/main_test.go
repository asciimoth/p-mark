package main

import (
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
