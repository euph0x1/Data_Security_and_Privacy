"""TLS client used by the devices. Verifies the server certificate against our self-signed CA."""
import json, socket, ssl
from certs import ensure_certs

HOST, PORT = "127.0.0.1", 8443


def request(obj: dict, host=HOST, port=PORT):
    cert, _ = ensure_certs()
    ctx = ssl.create_default_context(cafile=cert)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            s.sendall((json.dumps(obj) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
            info = {"tls_version": s.version(), "cipher": s.cipher()[0]}
    return json.loads(buf), info
