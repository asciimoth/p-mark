// Command pmark runs the process-marking daemon or watches the daemon's pinned
// process map.
//
// In daemon mode it installs regexp-based sample rules, optionally enables the
// fwmark consumer, exposes a local HTTP admin panel, and logs process events.
// In watcher mode it reads the pinned processes map and prints the currently
// marked process tree.
package main
