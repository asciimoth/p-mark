import os
import pathlib
import socket

runtime = pathlib.Path(os.environ["E2E_RUNTIME"])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mark = sock.getsockopt(socket.SOL_SOCKET, socket.SO_MARK)
runtime.joinpath("miss-mark").write_text(f"{mark}\n", encoding="ascii")
