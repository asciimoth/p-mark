import os
import pathlib
import time

runtime = pathlib.Path(os.environ["E2E_RUNTIME"])
runtime.joinpath("parent-ready").touch()
fork_signal = runtime / "fork-miss"
deadline = time.monotonic() + 30
while time.monotonic() <= deadline and not fork_signal.exists():
    time.sleep(0.01)
if not fork_signal.exists():
    raise SystemExit("timed out waiting to fork the non-matching child")

child = os.fork()
if child != 0:
    runtime.joinpath("child-pid").write_text(f"{child}\n", encoding="ascii")
    _, status = os.waitpid(child, 0)
    raise SystemExit(os.waitstatus_to_exitcode(status))

os.execv(
    "/usr/local/bin/e2e-kmiss",
    ["e2e-kmiss", str(runtime / "case" / "miss.py")],
)
