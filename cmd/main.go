package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

func main() {
	pinPath := flag.String("pin-path", "/sys/fs/bpf/ebpf-test", "bpffs directory for pinned maps")
	markName := flag.String("mark-name", "firefox", "comma-separated process identity substrings matched by the default check callback")
	markValue := flag.Uint64("mark-value", defaultMarkValue, "mark value assigned by the default check callback")
	markPriority := flag.Int("mark-priority", 0, "signed int8 priority assigned by the default check callback; higher priority wins")
	filesPriority := flag.Int("files-priority", 1, "signed int8 priority assigned by the files integration; higher priority wins")
	httpAddr := flag.String("http-addr", "127.0.0.1:8050", "daemon HTTP control listen address")
	watcher := flag.Bool("watcher", false, "watch the pinned process map instead of running the daemon")
	watchInterval := flag.Duration("watch-interval", time.Second, "interval for watcher refreshes")
	flag.Parse()
	if *markPriority < -128 || *markPriority > 127 {
		log.Fatalf("mark-priority must be between -128 and 127, got %d", *markPriority)
	}
	if *filesPriority < -128 || *filesPriority > 127 {
		log.Fatalf("files-priority must be between -128 and 127, got %d", *filesPriority)
	}
	priority := int8(*markPriority)

	if *watcher {
		if err := runWatcher(*pinPath, *watchInterval); err != nil {
			log.Fatal("Running watcher:", err)
		}
		return
	}

	currentFWMark := fwmark.FromMark(*markValue)
	log.Printf("Default mark %#x priority %d derives fwmark %s", *markValue, priority, fwmark.Format(currentFWMark))
	log.Printf("Drop marked traffic: %s", fwmarkDropCommand(currentFWMark))

	nameCheck := defaultCheck(*markName, priority, *markValue)
	daemon, err := core.NewDaemon(*pinPath, core.Callbacks{
		Check:         nameCheck,
		ProcessEvent:  logProcessEvent,
		ProcessUpdate: logProcessUpdate,
		Logf:          log.Printf,
	}, 0, 0) // TODO: Set up tcev and tttl via cli args
	if err != nil {
		log.Fatal("Creating daemon:", err)
	}

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

	if err := daemon.Run(); err != nil {
		log.Fatal("Running daemon:", err)
	}
	log.Printf("Pinned maps under %s", *pinPath)
	log.Print("Listening for process fork/exec/exit events. Press Ctrl-C to stop.")

	control, err := startDaemonControlServer(*httpAddr, daemon, *markName, priority, *markValue)
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

func startDaemonControlServer(addr string, daemon *core.Daemon, currentMarkName string, defaultMarkPriority int8, defaultMarkValue uint64) (*daemonControlServer, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	var controlMu sync.Mutex
	nameCheck := defaultCheck(currentMarkName, defaultMarkPriority, defaultMarkValue)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /mark-name", func(w http.ResponseWriter, r *http.Request) {
		update, err := parseMarkNameUpdate(r, defaultMarkPriority, defaultMarkValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		controlMu.Lock()
		nameCheck = defaultCheck(update.MarkName, update.MarkPriority, update.MarkValue)
		_, err = daemon.SetChecker(nameCheck)
		controlMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(update); err != nil {
			log.Printf("writing HTTP response: %v", err)
		}
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	control := &daemonControlServer{server: server}

	controlURL := httpControlURL(listener.Addr().String())
	log.Printf("Daemon HTTP control listening on %s", controlURL)
	log.Printf("Update checker: curl -X POST -d 'mark_name=%s' %s/mark-name", shellSingleQuoteValue(currentMarkName), controlURL)

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("daemon HTTP control server stopped: %v", err)
		}
	}()

	return control, nil
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

type markNameUpdate struct {
	MarkName     string `json:"mark_name"`
	MarkPriority int8   `json:"mark_priority"`
	MarkValue    uint64 `json:"mark_value"`
}

func parseMarkNameUpdate(r *http.Request, defaultMarkPriority int8, defaultMarkValue uint64) (markNameUpdate, error) {
	update := markNameUpdate{MarkPriority: defaultMarkPriority, MarkValue: defaultMarkValue}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			return markNameUpdate{}, fmt.Errorf("decode JSON body: %w", err)
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return markNameUpdate{}, fmt.Errorf("parse form body: %w", err)
		}
		update.MarkName = r.Form.Get("mark_name")
		if raw := r.Form.Get("mark_value"); raw != "" {
			markValue, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return markNameUpdate{}, fmt.Errorf("parse mark_value: %w", err)
			}
			update.MarkValue = markValue
		}
		if raw := r.Form.Get("mark_priority"); raw != "" {
			markPriority, err := strconv.ParseInt(raw, 10, 8)
			if err != nil {
				return markNameUpdate{}, fmt.Errorf("parse mark_priority: %w", err)
			}
			update.MarkPriority = int8(markPriority)
		}
	}

	update.MarkName = strings.TrimSpace(update.MarkName)
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

	branch := "`-"
	childPrefix := prefix + "  "
	if !last {
		branch = "|-"
		childPrefix = prefix + "| "
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

func defaultCheck(markName string, markPriority int8, markValue uint64) core.CheckFunc {
	markNames := parseMarkNames(markName)
	return func(info core.ProcessInfo) (int8, uint64, bool) {
		if len(markNames) == 0 {
			return 0, 0, false
		}
		return markPriority, markValue, processIdentityMatches(info, markNames)
	}
}

func parseMarkNames(markName string) []string {
	parts := strings.Split(markName, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func processIdentityMatches(info core.ProcessInfo, needles []string) bool {
	identity := []string{
		info.Comm,
		firstCmdlineField(info.Cmdline),
		info.Exe,
		filepath.Base(info.Exe),
	}
	pid := strconv.FormatUint(uint64(info.Key.Tgid), 10)
	for _, needle := range needles {
		if needle == pid {
			return true
		}
		if isDecimal(needle) {
			continue
		}
		for _, value := range identity {
			if value != "" && strings.Contains(value, needle) {
				return true
			}
		}
	}
	return false
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func firstCmdlineField(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
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
