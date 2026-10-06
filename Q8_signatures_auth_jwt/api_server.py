"""Part (b): Flask API with JWT authentication, role-based authorization and signed transactions."""
import datetime, threading
from functools import wraps
import jwt
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import make_server
from signatures import load_public, verify, canonical

SECRET = "lab8-demo-secret-change-me"      # HS256 signing secret (server only)
PORT = 5008

USERS = {
    "alice": {"pw": generate_password_hash("alice123"), "role": "customer", "balance": 10000.0, "pubkey": None},
    "bob":   {"pw": generate_password_hash("bob123"),   "role": "customer", "balance": 5000.0,  "pubkey": None},
    "admin": {"pw": generate_password_hash("admin123"), "role": "admin",    "balance": 0.0,     "pubkey": None},
}
LEDGER, SEEN_NONCES = [], set()


def token_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                return jsonify(error="401 Unauthorized: missing bearer token"), 401
            try:
                claims = jwt.decode(h[7:], SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify(error="401 Unauthorized: token expired"), 401
            except jwt.InvalidTokenError as e:
                return jsonify(error=f"401 Unauthorized: invalid token ({e})"), 401
            if role and claims.get("role") != role:                     # AUTHORIZATION
                return jsonify(error=f"403 Forbidden: requires role '{role}', you are '{claims.get('role')}'"), 403
            request.claims = claims
            return fn(*a, **k)
        return wrapper
    return deco


def create_app():
    app = Flask(__name__)

    @app.post("/api/login")                                              # AUTHENTICATION
    def login():
        d = request.get_json(force=True)
        u = USERS.get(d.get("username", ""))
        if not u or not check_password_hash(u["pw"], d.get("password", "")):
            return jsonify(error="401 Unauthorized: bad username or password"), 401
        ttl = min(max(int(d.get("ttl", 300)), 5), 3600)
        now = datetime.datetime.now(datetime.timezone.utc)
        token = jwt.encode({"sub": d["username"], "role": u["role"], "iat": now,
                            "exp": now + datetime.timedelta(seconds=ttl)}, SECRET, algorithm="HS256")
        return jsonify(token=token, expires_in=ttl)

    @app.get("/api/profile")
    @token_required()
    def profile():
        u = USERS[request.claims["sub"]]
        return jsonify(user=request.claims["sub"], role=u["role"], balance=u["balance"], has_public_key=bool(u["pubkey"]))

    @app.get("/api/admin/users")
    @token_required(role="admin")
    def users():
        return jsonify(users=[{"user": n, "role": u["role"], "balance": u["balance"]} for n, u in USERS.items()])

    @app.get("/api/admin/ledger")
    @token_required(role="admin")
    def ledger():
        return jsonify(ledger=LEDGER)

    @app.post("/api/keys")
    @token_required()
    def register_key():
        USERS[request.claims["sub"]]["pubkey"] = request.get_json(force=True)["public_key_pem"]
        return jsonify(ok=True, message="Public key registered")

    @app.post("/api/transfer")
    @token_required(role="customer")
    def transfer():
        d = request.get_json(force=True)
        me = request.claims["sub"]
        tx = {"from": me, "to": d.get("to"), "amount": d.get("amount"), "nonce": d.get("nonce")}
        if not USERS[me]["pubkey"]:
            return jsonify(error="No public key registered"), 400
        if tx["to"] not in USERS or not isinstance(tx["amount"], (int, float)) or tx["amount"] <= 0:
            return jsonify(error="Invalid transaction"), 400
        if tx["nonce"] in SEEN_NONCES:
            return jsonify(error="Replay detected: nonce already used"), 409
        import base64
        if not verify(load_public(USERS[me]["pubkey"]), base64.b64decode(d.get("signature", "")), canonical(tx)):
            return jsonify(error="Signature verification FAILED – transaction rejected"), 400
        if USERS[me]["balance"] < tx["amount"]:
            return jsonify(error="Insufficient funds"), 400
        SEEN_NONCES.add(tx["nonce"])
        USERS[me]["balance"] -= tx["amount"]; USERS[tx["to"]]["balance"] += tx["amount"]
        LEDGER.append({**tx, "signature": d["signature"][:32] + "…", "verified": True})
        return jsonify(ok=True, message="Signature valid – transfer executed", new_balance=USERS[me]["balance"])

    return app


def start_in_thread(port=PORT):
    srv = make_server("127.0.0.1", port, create_app(), threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    print(f"API on http://127.0.0.1:{PORT}")
    make_server("127.0.0.1", PORT, create_app(), threaded=True).serve_forever()
