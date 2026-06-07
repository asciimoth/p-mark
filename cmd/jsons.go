package main

type jsonProcessKey struct {
	TGID      uint32 `json:"tgid"`
	StartTime uint64 `json:"start_time"`
}

type jsonProcessValue struct {
	Tombstone  bool   `json:"tombstone"`
	Explicit   bool   `json:"explicit"`
	HasMark    bool   `json:"has_mark"`
	Priority   int8   `json:"priority"`
	Generation uint64 `json:"generation"`
	Mark       uint64 `json:"mark,omitempty"`
	Timestamp  uint64 `json:"timestamp"`
}

type jsonProcInfo struct {
	PPID    uint32 `json:"ppid"`
	Comm    string `json:"comm,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Exe     string `json:"exe,omitempty"`
}

type jsonProcessEvent struct {
	Type      string            `json:"type"`
	Key       jsonProcessKey    `json:"key"`
	ParentKey *jsonProcessKey   `json:"parent_key,omitempty"`
	Kernel    jsonKernelMark    `json:"kernel"`
	Process   jsonProcInfo      `json:"process"`
	Value     *jsonProcessValue `json:"value,omitempty"`
}

type jsonKernelMark struct {
	HasMark   bool   `json:"has_mark"`
	Inherited bool   `json:"inherited"`
	Priority  int8   `json:"priority"`
	Mark      uint64 `json:"mark,omitempty"`
}

type jsonProcessUpdate struct {
	Type  string           `json:"type"`
	Key   jsonProcessKey   `json:"key"`
	Value jsonProcessValue `json:"value"`
}

type jsonDaemonState struct {
	Type        string                 `json:"type"`
	RefreshedAt string                 `json:"refreshed_at"`
	Config      daemonControlConfig    `json:"config"`
	Dynamic     jsonDaemonDynamicState `json:"dynamic"`
}

type jsonDaemonDynamicState struct {
	Generation uint64                `json:"generation"`
	ProcessMap jsonProcessMapState   `json:"process_map"`
	Processes  []jsonObservedProcess `json:"processes"`
}

type jsonProcessMapState struct {
	Alive      int                   `json:"alive"`
	Tombstones int                   `json:"tombstones"`
	Latest     uint64                `json:"latest"`
	Entries    []jsonProcessMapEntry `json:"entries"`
}

type jsonProcessMapEntry struct {
	Key   jsonProcessKey   `json:"key"`
	Value jsonProcessValue `json:"value"`
}

type jsonObservedProcess struct {
	Key  jsonProcessKey `json:"key"`
	Info jsonProcInfo   `json:"info"`
}
