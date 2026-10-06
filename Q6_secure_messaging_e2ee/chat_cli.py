"""Optional real two-terminal demo:  python chat_cli.py alice bob   /   python chat_cli.py bob alice
(start relay_server.py first)."""
import sys, threading, time
from e2ee import Device, fingerprint
from client import request

me, peer = sys.argv[1], sys.argv[2]
dev = Device(me)
request({"type": "register", "id": me, "pubkey": dev.public_hex})
print(f"[{me}] registered. Waiting for {peer} ...")
while True:
    r, _ = request({"type": "get_key", "id": peer})
    if r["ok"]:
        peer_key = r["pubkey"]; break
    time.sleep(1)
print("Safety number (compare with", peer, "):", fingerprint(dev.public_hex, peer_key))


def poll():
    while True:
        r, _ = request({"type": "fetch", "id": me})
        for m in r["messages"]:
            print(f"\n<{peer}> {dev.decrypt(m, peer_key)}\n> ", end="", flush=True)
        time.sleep(1)


threading.Thread(target=poll, daemon=True).start()
while True:
    text = input("> ")
    request({"type": "send", **dev.encrypt(peer, peer_key, text)})
