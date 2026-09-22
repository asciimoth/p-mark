import fcntl
import os
import pathlib
import socket

runtime = pathlib.Path(os.environ["E2E_RUNTIME"])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mark = sock.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
with runtime.joinpath("matched-marks").open("a", encoding="ascii") as output:
    fcntl.flock(output, fcntl.LOCK_EX)
    output.write(f"{mark}\n")
