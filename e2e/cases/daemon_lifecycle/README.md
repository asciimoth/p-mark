# daemon_lifecycle

Runs the real daemon and checks its HTTP control surface and process map.

Assertions:

- a process selected by `comm` gets the configured explicit mark;
- its child inherits the mark;
- a control API rule update removes both marks and advances the generation;
- restoring the rule applies a new mark to both live processes;
- a dynamic multirule records the matching process and can be removed;
- exited tracked processes become tombstones.

