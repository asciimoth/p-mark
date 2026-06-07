package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	core "github.com/asciimoth/p-mark"
	"github.com/asciimoth/p-mark/fwmark"
)

const defaultMarkValue = 0xeb9f000100000001

//go:embed admin.html
var adminHTML string

func main() {
	pinPath := flag.String("pin-path", "/sys/fs/bpf/ebpf-test", "bpffs directory for pinned maps")
	ruleComm := flag.String("rule-comm", "firefox", "comma-separated regexps matched against comm by the default check callback")
	ruleCmd := flag.String("rule-cmd", "", "comma-separated regexps matched against cmdline by the default check callback")
	ruleExe := flag.String("rule-exe", "", "comma-separated regexps matched against exe and exe basename by the default check callback")
	rulePPID := flag.String("rule-ppid", "", "comma-separated parent process ids matched by the default check callback")
	markValue := flag.Uint64("mark-value", defaultMarkValue, "mark value assigned by the default check callback")
	fwmarkValue := flag.String("fmark-value", "", "fwmark format value to derive full mark from; overwrites mark-value")
	enableFWMark := flag.Bool("fwmark", false, "enable Linux fwmark socket marking with fwmark eBPF hooks in daemon mode")
	markPriority := flag.Int("mark-priority", 0, "signed int8 priority assigned by the default check callback; higher priority wins")
	httpAddr := flag.String("http-addr", "127.0.0.1:8050", "daemon HTTP control listen address")
	watcher := flag.Bool("watcher", false, "watch the pinned process map instead of running the daemon")
	watchInterval := flag.Duration("watch-interval", time.Second, "interval for watcher refreshes")
	flag.Parse()
	if *markPriority < -128 || *markPriority > 127 {
		log.Fatalf("mark-priority must be between -128 and 127, got %d", *markPriority)
	}
	priority := int8(*markPriority)

	if *watcher {
		if err := runWatcher(*pinPath, *watchInterval); err != nil {
			log.Fatal("Running watcher:", err)
		}
		return
	}

	if *fwmarkValue != "" && !*enableFWMark {
		log.Fatal("fmark-value requires -fwmark")
	}
	if *fwmarkValue != "" {
		fwm, err := fwmark.Parse(*fwmarkValue)
		if err != nil {
			log.Fatalf("Failed to parse fwmark: %v", err)
		}
		mark := fwmark.ToMark(fwm)
		markValue = &mark
	}

	if *enableFWMark {
		currentFWMark := fwmark.FromMark(*markValue)
		log.Printf("Default mark %#x priority %d derives fwmark %s", *markValue, priority, fwmark.Format(currentFWMark))
		log.Printf("Drop marked traffic: %s", fwmarkDropCommand(currentFWMark))
	}

	checkRules := defaultCheckRules{
		RuleComm: *ruleComm,
		RuleCmd:  *ruleCmd,
		RuleExe:  *ruleExe,
		RulePPID: *rulePPID,
	}
	nameCheck, err := defaultCheck(checkRules, priority, *markValue)
	if err != nil {
		log.Fatal("Creating default checker:", err)
	}
	daemon, err := core.NewDaemon(*pinPath, core.Callbacks{
		Check:         nameCheck,
		ProcessEvent:  logProcessEvent,
		ProcessUpdate: logProcessUpdate,
		Logf:          log.Printf,
	}, 0, 0) // TODO: Set up tcev and tttl via cli args
	if err != nil {
		log.Fatal("Creating daemon:", err)
	}

	if *enableFWMark {
		fwmarks, err := fwmark.NewManager(*pinPath, log.Printf)
		if err != nil {
			log.Fatal("Setting up fwmark eBPF hooks:", err)
		}
		defer func() {
			if err := fwmarks.Close(); err != nil {
				log.Printf("Closing fwmark hooks: %v", err)
			}
		}()

		fwmarkProcessUpdate := fwmarks.ProcessUpdateCallback()
		daemon.UpdateHooks(core.Callbacks{
			ProcessEvent: logProcessEvent,
			ProcessUpdate: func(update core.ProcessUpdate) {
				fwmarkProcessUpdate(update)
				logProcessUpdate(update)
			},
			Logf: log.Printf,
		})
	}

	if err := daemon.Run(); err != nil {
		log.Fatal("Running daemon:", err)
	}
	log.Printf("Pinned maps under %s", *pinPath)
	log.Print("Listening for process fork/exec/exit events. Press Ctrl-C to stop.")

	control, err := startDaemonControlServer(*httpAddr, daemon, daemonControlConfig{
		PinPath:       *pinPath,
		HTTPAddr:      *httpAddr,
		FWMarkEnabled: *enableFWMark,
		Rules:         checkRules,
		MarkPriority:  priority,
		MarkValue:     *markValue,
	})
	if err != nil {
		log.Fatal("Starting daemon HTTP control server:", err)
	}
	defer control.shutdown()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	select {
	case <-stop:
		log.Print("Received signal, exiting.")
		if err := daemon.Stop(); err != nil {
			log.Fatal("Stopping daemon:", err)
		}
	case err := <-daemon.Done():
		if err != nil {
			log.Fatal("Daemon stopped:", err)
		}
	}
}

type daemonControlServer struct {
	server *http.Server
}

type daemonControlConfig struct {
	PinPath       string            `json:"pin_path"`
	HTTPAddr      string            `json:"http_addr"`
	FWMarkEnabled bool              `json:"fwmark_enabled"`
	Rules         defaultCheckRules `json:"rules"`
	MarkPriority  int8              `json:"mark_priority"`
	MarkValue     uint64            `json:"mark_value,string"`
}

func startDaemonControlServer(addr string, daemon *core.Daemon, config daemonControlConfig) (*daemonControlServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	config.HTTPAddr = listener.Addr().String()

	var controlMu sync.Mutex
	nameCheck, err := defaultCheck(config.Rules, config.MarkPriority, config.MarkValue)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(adminHTML))
	})
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, r *http.Request) {
		controlMu.Lock()
		stateConfig := config
		controlMu.Unlock()

		state, err := daemonControlState(daemon, stateConfig)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(state); err != nil {
			log.Printf("writing HTTP response: %v", err)
		}
	})
	handleRuleUpdate := func(w http.ResponseWriter, r *http.Request) {
		controlMu.Lock()
		currentMarkPriority := config.MarkPriority
		currentMarkValue := config.MarkValue
		controlMu.Unlock()

		update, err := parseDefaultCheckUpdate(r, currentMarkPriority, currentMarkValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		nextCheck, err := defaultCheck(update.Rules, update.MarkPriority, update.MarkValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		controlMu.Lock()
		nameCheck = nextCheck
		_, err = daemon.SetChecker(nameCheck)
		if err == nil {
			config.Rules = update.Rules
			config.MarkPriority = update.MarkPriority
			config.MarkValue = update.MarkValue
		}
		controlMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(update); err != nil {
			log.Printf("writing HTTP response: %v", err)
		}
	}
	mux.HandleFunc("POST /rules", handleRuleUpdate)
	mux.HandleFunc("POST /mark-name", handleRuleUpdate)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	control := &daemonControlServer{server: server}

	controlURL := httpControlURL(listener.Addr().String())
	log.Printf("Daemon HTTP control listening on %s", controlURL)
	log.Printf(
		"Update checker: curl -X POST -d 'rule_comm=%s' -d 'rule_cmd=%s' -d 'rule_exe=%s' -d 'rule_ppid=%s' %s/rules",
		shellSingleQuoteValue(config.Rules.RuleComm),
		shellSingleQuoteValue(config.Rules.RuleCmd),
		shellSingleQuoteValue(config.Rules.RuleExe),
		shellSingleQuoteValue(config.Rules.RulePPID),
		controlURL,
	)

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("daemon HTTP control server stopped: %v", err)
		}
	}()

	return control, nil
}

func daemonControlState(daemon *core.Daemon, config daemonControlConfig) (jsonDaemonState, error) {
	snapshot, err := core.GrabProcessMapState(config.PinPath)
	if err != nil {
		return jsonDaemonState{}, err
	}

	entries := make([]jsonProcessMapEntry, 0, len(snapshot.Entries))
	for key, value := range snapshot.Entries {
		entries = append(entries, jsonProcessMapEntry{
			Key:   jsonKey(key),
			Value: jsonValue(value),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Key.TGID != entries[j].Key.TGID {
			return entries[i].Key.TGID < entries[j].Key.TGID
		}
		return entries[i].Key.StartTime < entries[j].Key.StartTime
	})

	procs := make([]jsonObservedProcess, 0, len(snapshot.Procs))
	for _, proc := range snapshot.Procs {
		procs = append(procs, jsonObservedProcess{
			Key:  jsonKey(proc.Key),
			Info: jsonProc(proc),
		})
	}
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].Key.TGID != procs[j].Key.TGID {
			return procs[i].Key.TGID < procs[j].Key.TGID
		}
		return procs[i].Key.StartTime < procs[j].Key.StartTime
	})

	return jsonDaemonState{
		Type:        "daemon_state",
		RefreshedAt: time.Now().Format(time.RFC3339),
		Config:      config,
		Dynamic: jsonDaemonDynamicState{
			Generation: daemon.CurrentGeneration(),
			ProcessMap: jsonProcessMapState{
				Alive:      snapshot.Alive,
				Tombstones: snapshot.Tombstones,
				Latest:     snapshot.Latest,
				Entries:    entries,
			},
			Processes: procs,
		},
	}, nil
}

func (s *daemonControlServer) shutdown() {
	if s == nil || s.server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		log.Printf("stopping daemon HTTP control server: %v", err)
	}
}

type defaultCheckRules struct {
	RuleComm string `json:"rule_comm"`
	RuleCmd  string `json:"rule_cmd"`
	RuleExe  string `json:"rule_exe"`
	RulePPID string `json:"rule_ppid"`
}

type defaultCheckUpdate struct {
	defaultCheckRules
	Rules        defaultCheckRules `json:"-"`
	MarkPriority int8              `json:"mark_priority"`
	MarkValue    uint64            `json:"mark_value"`
}

func parseDefaultCheckUpdate(r *http.Request, defaultMarkPriority int8, defaultMarkValue uint64) (defaultCheckUpdate, error) {
	update := defaultCheckUpdate{MarkPriority: defaultMarkPriority, MarkValue: defaultMarkValue}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			return defaultCheckUpdate{}, fmt.Errorf("decode JSON body: %w", err)
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return defaultCheckUpdate{}, fmt.Errorf("parse form body: %w", err)
		}
		update.RuleComm = r.Form.Get("rule_comm")
		update.RuleCmd = r.Form.Get("rule_cmd")
		update.RuleExe = r.Form.Get("rule_exe")
		update.RulePPID = r.Form.Get("rule_ppid")
		if raw := r.Form.Get("mark_value"); raw != "" {
			markValue, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return defaultCheckUpdate{}, fmt.Errorf("parse mark_value: %w", err)
			}
			update.MarkValue = markValue
		}
		if raw := r.Form.Get("mark_priority"); raw != "" {
			markPriority, err := strconv.ParseInt(raw, 10, 8)
			if err != nil {
				return defaultCheckUpdate{}, fmt.Errorf("parse mark_priority: %w", err)
			}
			update.MarkPriority = int8(markPriority)
		}
	}

	update.Rules = defaultCheckRules{
		RuleComm: strings.TrimSpace(update.RuleComm),
		RuleCmd:  strings.TrimSpace(update.RuleCmd),
		RuleExe:  strings.TrimSpace(update.RuleExe),
		RulePPID: strings.TrimSpace(update.RulePPID),
	}
	update.defaultCheckRules = update.Rules
	return update, nil
}

func httpControlURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func shellSingleQuoteValue(value string) string {
	return strings.ReplaceAll(value, "'", `'\''`)
}

func fwmarkDropCommand(mark uint32) string {
	formattedMark := fwmark.Format(mark)
	return fmt.Sprintf(
		"sudo nft delete table inet ebpf_test_fwmark 2>/dev/null || true; sudo nft add table inet ebpf_test_fwmark; sudo nft 'add chain inet ebpf_test_fwmark output { type filter hook output priority 0; policy accept; }'; sudo nft add rule inet ebpf_test_fwmark output meta mark %s counter drop; sudo nft add rule inet ebpf_test_fwmark output socket mark %s counter drop; sudo nft list chain inet ebpf_test_fwmark output",
		formattedMark,
		formattedMark,
	)
}

type watcherTombstoneTracker struct {
	seen      map[core.ProcessKey]bool
	collected int
}

func newWatcherTombstoneTracker() *watcherTombstoneTracker {
	return &watcherTombstoneTracker{
		seen: make(map[core.ProcessKey]bool),
	}
}

func (t *watcherTombstoneTracker) update(snapshot core.ProcessMapState) {
	for key, value := range snapshot.Entries {
		if value.Tombstone {
			if _, ok := t.seen[key]; !ok {
				t.seen[key] = false
			}
		}
	}

	for key, removed := range t.seen {
		if removed {
			continue
		}
		if _, ok := snapshot.Entries[key]; ok {
			continue
		}
		t.seen[key] = true
		t.collected++
	}
}

func (t *watcherTombstoneTracker) observed() int {
	return len(t.seen)
}

func runWatcher(pinPath string, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)

	tombstones := newWatcherTombstoneTracker()
	if err := printWatcherSnapshot(pinPath, tombstones); err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			fmt.Println()
			return nil
		case <-ticker.C:
			if err := printWatcherSnapshot(pinPath, tombstones); err != nil {
				return err
			}
		}
	}
}

func printWatcherSnapshot(pinPath string, tombstones *watcherTombstoneTracker) error {
	snapshot, err := core.GrabProcessMapState(pinPath)
	if err != nil {
		return err
	}
	tombstones.update(snapshot)

	fmt.Print("\033[H\033[2J")
	fmt.Printf("Process map watcher: %s\n", filepath.Join(pinPath, "processes"))
	fmt.Printf("Refreshed: %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Alive entries: %d\n", snapshot.Alive)
	fmt.Printf("Tombstones: %d\n", snapshot.Tombstones)
	fmt.Printf("Observed tombstones: %d\n", tombstones.observed())
	fmt.Printf("Collected tombstones: %d\n", tombstones.collected)
	fmt.Printf("Latest entry update: %s\n\n", formatLatestUpdate(snapshot.Latest))
	fmt.Println("Process tree:")

	if !printWatcherTree(snapshot) {
		fmt.Println("  no live process map entries match current /proc processes")
	}

	return nil
}

func printWatcherTree(snapshot core.ProcessMapState) bool {
	byPID := make(map[uint32]core.ProcessInfo, len(snapshot.Procs))
	byParent := make(map[uint32][]core.ProcessInfo)
	active := make(map[core.ProcessKey]core.ProcessValue)

	for key, value := range snapshot.Entries {
		if !value.Tombstone && value.HasMark {
			active[key] = value
		}
	}
	for _, proc := range snapshot.Procs {
		byPID[proc.Key.Tgid] = proc
		byParent[proc.PPID] = append(byParent[proc.PPID], proc)
	}
	for ppid := range byParent {
		sort.Slice(byParent[ppid], func(i, j int) bool {
			return byParent[ppid][i].Key.Tgid < byParent[ppid][j].Key.Tgid
		})
	}

	roots := make([]core.ProcessInfo, 0)
	for key := range active {
		proc, ok := byPID[key.Tgid]
		if !ok || proc.Key.StartTime != key.StartTime || hasActiveAncestor(proc, byPID, active) {
			continue
		}
		roots = append(roots, proc)
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Key.Tgid < roots[j].Key.Tgid
	})

	for _, root := range roots {
		printWatcherNode(root, "", true, byParent, active, make(map[uint32]bool))
	}
	return len(roots) > 0
}

func hasActiveAncestor(proc core.ProcessInfo, byPID map[uint32]core.ProcessInfo, active map[core.ProcessKey]core.ProcessValue) bool {
	seen := make(map[uint32]bool)
	for ppid := proc.PPID; ppid != 0; {
		if seen[ppid] {
			return false
		}
		seen[ppid] = true

		parent, ok := byPID[ppid]
		if !ok {
			return false
		}
		if _, ok := active[parent.Key]; ok {
			return true
		}
		ppid = parent.PPID
	}
	return false
}

func printWatcherNode(
	proc core.ProcessInfo,
	prefix string,
	last bool,
	byParent map[uint32][]core.ProcessInfo,
	active map[core.ProcessKey]core.ProcessValue,
	seen map[uint32]bool,
) {
	if seen[proc.Key.Tgid] {
		return
	}
	seen[proc.Key.Tgid] = true

	branch := "└"
	if prefix == "" {
		branch = ""
	}
	childPrefix := prefix + " "
	if !last {
		branch = "├"
		childPrefix = prefix + "│"
	}

	value := active[proc.Key]
	fmt.Printf("%s%s %d %s %s\n", prefix, branch, proc.Key.Tgid, shortProcessName(proc), formatProcessMark(value, true))

	children := activeWatcherChildren(proc, byParent, active, seen)
	for i, child := range children {
		printWatcherNode(child, childPrefix, i == len(children)-1, byParent, active, seen)
	}
}

func activeWatcherChildren(
	proc core.ProcessInfo,
	byParent map[uint32][]core.ProcessInfo,
	active map[core.ProcessKey]core.ProcessValue,
	seen map[uint32]bool,
) []core.ProcessInfo {
	var children []core.ProcessInfo
	var walk func(parent core.ProcessInfo)
	walk = func(parent core.ProcessInfo) {
		for _, child := range byParent[parent.Key.Tgid] {
			if seen[child.Key.Tgid] {
				continue
			}
			if _, ok := active[child.Key]; ok {
				children = append(children, child)
				continue
			}
			walk(child)
		}
	}
	walk(proc)
	return children
}

func defaultCheck(rules defaultCheckRules, markPriority int8, markValue uint64) (core.CheckFunc, error) {
	matcher, err := compileDefaultCheckRules(rules)
	if err != nil {
		return nil, err
	}
	return func(info core.ProcessInfo) (int8, uint64, bool) {
		if !matcher.hasRules() {
			return 0, 0, false
		}
		return markPriority, markValue, matcher.matches(info)
	}, nil
}

type defaultCheckMatcher struct {
	comm []*regexp.Regexp
	cmd  []*regexp.Regexp
	exe  []*regexp.Regexp
	ppid map[uint32]bool
}

func compileDefaultCheckRules(rules defaultCheckRules) (defaultCheckMatcher, error) {
	comm, err := compileRegexpList("rule_comm", rules.RuleComm)
	if err != nil {
		return defaultCheckMatcher{}, err
	}
	cmd, err := compileRegexpList("rule_cmd", rules.RuleCmd)
	if err != nil {
		return defaultCheckMatcher{}, err
	}
	exe, err := compileRegexpList("rule_exe", rules.RuleExe)
	if err != nil {
		return defaultCheckMatcher{}, err
	}
	ppid, err := parsePPIDRules(rules.RulePPID)
	if err != nil {
		return defaultCheckMatcher{}, err
	}
	return defaultCheckMatcher{
		comm: comm,
		cmd:  cmd,
		exe:  exe,
		ppid: ppid,
	}, nil
}

func compileRegexpList(name, value string) ([]*regexp.Regexp, error) {
	parts := strings.Split(value, ",")
	out := make([]*regexp.Regexp, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		re, err := regexp.Compile(part)
		if err != nil {
			return nil, fmt.Errorf("compile %s %q: %w", name, part, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func parsePPIDRules(value string) (map[uint32]bool, error) {
	parts := strings.Split(value, ",")
	out := make(map[uint32]bool)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ppid, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse rule_ppid %q: %w", part, err)
		}
		out[uint32(ppid)] = true
	}
	return out, nil
}

func (m defaultCheckMatcher) hasRules() bool {
	return len(m.comm) > 0 || len(m.cmd) > 0 || len(m.exe) > 0 || len(m.ppid) > 0
}

func (m defaultCheckMatcher) matches(info core.ProcessInfo) bool {
	if m.ppid[info.PPID] {
		return true
	}
	if anyRegexpMatches(m.comm, info.Comm) {
		return true
	}
	if anyRegexpMatches(m.cmd, info.Cmdline) {
		return true
	}
	if anyRegexpMatches(m.exe, info.Exe) {
		return true
	}
	if anyRegexpMatches(m.exe, filepath.Base(info.Exe)) {
		return true
	}
	return false
}

func anyRegexpMatches(regexps []*regexp.Regexp, value string) bool {
	if value == "" {
		return false
	}
	for _, re := range regexps {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func logProcessEvent(event core.ProcessEvent) {
	logJSON("process event", jsonProcessEvent{
		Type:      event.Type,
		Key:       jsonKey(event.Key),
		ParentKey: ptrJSONKey(event.ParentKey),
		Kernel: jsonKernelMark{
			HasMark:   event.Kernel.HasMark,
			Inherited: event.Kernel.Inherited,
			Priority:  event.Kernel.Priority,
			Mark:      event.Kernel.Mark,
		},
		Process: jsonProc(event.Process),
		Value:   ptrJSONValue(event.Value),
	})
}

func logProcessUpdate(update core.ProcessUpdate) {
	logJSON("process update", jsonProcessUpdate{
		Type:  "process_update",
		Key:   jsonKey(update.Key),
		Value: jsonValue(update.Value),
	})
}

func logJSON(label string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Printf("%s: %v", label, value)
		return
	}
	log.Printf("%s:\n%s", label, data)
}

func jsonKey(key core.ProcessKey) jsonProcessKey {
	return jsonProcessKey{
		TGID:      key.Tgid,
		StartTime: key.StartTime,
	}
}

func ptrJSONKey(key *core.ProcessKey) *jsonProcessKey {
	if key == nil {
		return nil
	}
	out := jsonKey(*key)
	return &out
}

func jsonValue(value core.ProcessValue) jsonProcessValue {
	return jsonProcessValue{
		Tombstone:  value.Tombstone,
		Explicit:   value.Inheritance,
		HasMark:    value.HasMark,
		Priority:   value.Priority,
		Generation: value.Generation,
		Mark:       value.Mark,
		Timestamp:  value.Timestamp,
	}
}

func ptrJSONValue(value *core.ProcessValue) *jsonProcessValue {
	if value == nil {
		return nil
	}
	out := jsonValue(*value)
	return &out
}

func jsonProc(info core.ProcessInfo) jsonProcInfo {
	return jsonProcInfo{
		PPID:    info.PPID,
		Comm:    info.Comm,
		Cmdline: info.Cmdline,
		Exe:     info.Exe,
	}
}

func shortProcessName(proc core.ProcessInfo) string {
	if proc.Comm != "" {
		return proc.Comm
	}
	if proc.Cmdline != "" {
		fields := strings.Fields(proc.Cmdline)
		if len(fields) > 0 {
			return fields[0]
		}
	}
	if proc.Exe != "" {
		return filepath.Base(proc.Exe)
	}
	return "unknown"
}

func formatProcessMark(value core.ProcessValue, hasMark bool) string {
	if !hasMark {
		return "no mark"
	}
	if !value.HasMark {
		return fmt.Sprintf("no mark priority=%d gen=%d", value.Priority, value.Generation)
	}
	return fmt.Sprintf("mark=%d priority=%d gen=%d", value.Mark, value.Priority, value.Generation)
}

func formatLatestUpdate(timestamp uint64) string {
	if timestamp == 0 {
		return "none"
	}

	now := procUptimeNS()
	age := time.Duration(0)
	if timestamp <= now {
		age = time.Duration(now - timestamp)
	}
	wall := time.Now().Add(-age)
	return fmt.Sprintf("%d (%s ago, boot_ns=%d)", wall.Unix(), formatAge(age), timestamp)
}

func formatAge(age time.Duration) string {
	if age < time.Second {
		return age.Truncate(time.Millisecond).String()
	}
	if age < time.Minute {
		return age.Truncate(time.Second).String()
	}
	if age < time.Hour {
		return age.Truncate(time.Minute).String()
	}
	if age < 24*time.Hour {
		return age.Truncate(time.Hour).String()
	}
	return age.Truncate(24 * time.Hour).String()
}

func procUptimeNS() uint64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return uint64(seconds * float64(time.Second))
}
