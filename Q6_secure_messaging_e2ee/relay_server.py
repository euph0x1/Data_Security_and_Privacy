"""TLS message-relay server. It stores public keys + ciphertext only. It has NO access to plaintext."""
import json, socketserver, ssl, threading, time
from certs import ensure_certs


class RelayState:
    def __init__(self):
        self.lock = threading.Lock()
        self.keys, self.inbox, self.log = {}, {}, []

    def _log(self, kind, req):
        self.log.append({"time": time.strftime("%H:%M:%S"), "type": kind, "frame_seen_by_server": req})

    def process(self, req: dict) -> dict:
        t = req.get("type")
        with self.lock:
            self._log(t, req)
            if t == "register":
                self.keys[req["id"]] = req["pubkey"]
                self.inbox.setdefault(req["id"], [])
                return {"ok": True}
            if t == "get_key":
                k = self.keys.get(req["id"])
                return {"ok": k is not None, "pubkey": k}
            if t == "send":                                   # relay ciphertext blindly
                self.inbox.setdefault(req["to"], []).append(req)
                return {"ok": True}
            if t == "fetch":
                msgs, self.inbox[req["id"]] = self.inbox.get(req["id"], []), []
                return {"ok": True, "messages": msgs}
        return {"ok": False, "error": "unknown request"}


class _Handler(socketserver.StreamRequestHandler):
    def setup(self):
        self.request.do_handshake()          # TLS handshake happens here
        super().setup()

    def handle(self):
        line = self.rfile.readline(2_000_000)
        if not line:
            return
        try:
            resp = self.server.state.process(json.loads(line))
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
        self.wfile.write((json.dumps(resp) + "\n").encode())


class TLSRelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host="127.0.0.1", port=8443):
        cert, key = ensure_certs()
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(cert, key)
        self.state = RelayState()
        super().__init__((host, port), _Handler)

    def get_request(self):
        sock, addr = super().get_request()
        return self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):   # silence failed handshakes
        pass


def start_in_thread(host="127.0.0.1", port=8443) -> TLSRelayServer:
    srv = TLSRelayServer(host, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    srv = TLSRelayServer()
    print("TLS relay listening on 127.0.0.1:8443  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
