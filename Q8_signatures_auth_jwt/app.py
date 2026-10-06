import base64, json, uuid
import jwt, requests
import streamlit as st
import signatures as S
from api_server import start_in_thread, PORT
from diagrams import sequence_svg, show_svg

st.set_page_config(page_title="Q8 · Signatures, AuthN & AuthZ", page_icon="✍️", layout="wide")


@st.cache_resource
def get_server():
    return start_in_thread()          # Flask API runs in a background thread


get_server()
API = f"http://127.0.0.1:{PORT}/api"
ss = st.session_state
for k, v in {"key": None, "sig": None, "token": None, "log": [], "tx_key": None}.items():
    ss.setdefault(k, v)


def call(method, path, **kw):
    headers = {"Authorization": f"Bearer {ss.token}"} if ss.token else {}
    r = requests.request(method, API + path, headers=headers, timeout=5, **kw)
    ss.log.insert(0, f"{method} {path} → {r.status_code}")
    return r


st.title("✍️ Q8 · Digital Signatures, Authentication & Authorization")
tabs = st.tabs(["📐 Architecture", "🔁 Sequence diagram", "✍️ (a) RSA signatures", "🔑 (b) Login + JWT", "🏦 Case study"])

# ---------------------------------------------------------------- ARCHITECTURE
with tabs[0]:
    st.subheader("System architecture")
    st.graphviz_chart('''
    digraph G { rankdir=LR; node [shape=box, style="rounded,filled", fontname=Helvetica, fillcolor="#e8f0fe"];
      subgraph cluster_c { label="Streamlit front-end (client)"; style=dashed;
        L [label="Login form"]; SG [label="RSA signing\\n(private key in browser session)", fillcolor="#fce8e6"]; UI [label="API-call panels\\n+ JWT inspector"]; }
      subgraph cluster_s { label="Flask REST API (127.0.0.1:5008)"; style=dashed;
        AU [label="/login\\nverify password hash\\nissue JWT (HS256, exp)", fillcolor="#e6f4ea"];
        MW [label="@token_required\\nverify JWT signature + expiry\\ncheck role (RBAC)", fillcolor="#fef7e0"];
        EP [label="Protected endpoints\\n/profile /admin/* /keys /transfer"];
        VF [label="RSA-PSS verify\\n+ nonce replay check", fillcolor="#e6f4ea"]; AU -> MW [style=invis]; MW -> EP; EP -> VF; }
      DB [label="In-memory store\\nusers · public keys · ledger", shape=cylinder, fillcolor="#f1f3f4"];
      L -> AU [label="credentials"]; AU -> UI [label="JWT", style=dashed];
      UI -> MW [label="Bearer JWT"]; SG -> EP [label="signed tx + signature"]; VF -> DB; }''')
    st.markdown("""
| Concept | Question answered | Mechanism in this project |
|---|---|---|
| **Authentication** | *Who are you?* | Username + hashed password (`werkzeug`) → server issues a **JWT** |
| **Authorization** | *What may you do?* | `role` claim inside JWT checked by `@token_required(role=…)` → **403** if not allowed |
| **Digital signature** | *Did this exact content come from you, unmodified?* | **RSA-PSS + SHA-256**: sign with private key, verify with public key |

**Two different cryptographic ideas:** the JWT uses a *symmetric* HMAC-SHA256 secret held by the server (proves the server issued the token).
The transaction signature uses *asymmetric* RSA – only the customer holds the private key, so the bank can prove **non-repudiation**.
Roles: `alice`/`bob` = customer (pw `alice123`/`bob123`), `admin` (pw `admin123`).
""")

# ---------------------------------------------------------------- SEQUENCE
with tabs[1]:
    st.subheader("Sequence: login → token → signed transfer")
    P = ["Customer (Streamlit)", "Flask API", "Ledger / DB"]
    steps = [
        (0, 1, "1. POST /login {user, password}", "plain"),
        (1, 1, "2. check_password_hash → issue JWT(role, exp)", "e2ee"),
        (1, 0, "3. 200 {token}", "plain", True),
        (0, 1, "4. POST /keys  Bearer JWT  {publicKeyPEM}", "tls"),
        (0, 0, "5. tx={to,amount,nonce}; sig = RSA-PSS(privKey, tx)", "sig"),
        (0, 1, "6. POST /transfer  Bearer JWT  {tx, sig}", "tls"),
        (1, 1, "7. verify JWT signature, expiry, role=customer", "e2ee"),
        (1, 1, "8. verify RSA sig with stored pubKey + nonce unused", "sig"),
        (1, 2, "9. debit / credit, append ledger", "plain"),
        (1, 0, "10. 200 executed  (or 401/403/400 on failure)", "plain", True),
    ]
    svg, h = sequence_svg(P, steps, col_w=330)
    show_svg(svg)
    st.caption("blue = authenticated request · orange = digital-signature step · green = server-side verification")

# ---------------------------------------------------------------- (a) RSA
with tabs[2]:
    st.subheader("(a) RSA digital signature – generate, sign, verify")
    c1, c2 = st.columns(2)
    bits = c1.selectbox("Key size", [2048, 3072], 0)
    scheme = c2.radio("Padding scheme", ["PSS", "PKCS1v15"], horizontal=True)
    if st.button("🔑 Generate RSA key pair"):
        ss.key, ss.sig = S.generate_keypair(bits), None
    if ss.key:
        with st.expander("View keys"):
            st.code(S.public_pem(ss.key)); st.code(S.private_pem(ss.key)[:200] + "\n… (private key – never share)")
        msg = st.text_area("Message to sign", "Pay Bob $100 for invoice #42")
        if st.button("✍️ Sign"):
            ss.sig = S.sign(ss.key, msg.encode(), scheme)
        if ss.sig:
            st.code(ss.sig.hex(), language="text")
            st.markdown("**Verify** (edit the message to see it fail):")
            msg2 = st.text_input("Message received", msg)
            ok = S.verify(ss.key.public_key(), ss.sig, msg2.encode(), scheme)
            st.success("✅ Signature VALID – authentic and unmodified") if ok else st.error("❌ Signature INVALID – message altered or wrong key")
        st.markdown("**Sign a file**")
        f = st.file_uploader("Upload file")
        if f:
            fs = S.sign(ss.key, f.getvalue(), scheme)
            st.code(fs.hex()[:96] + "…"); st.caption(f"{len(f.getvalue())} bytes signed; verify = {S.verify(ss.key.public_key(), fs, f.getvalue(), scheme)}")
    else:
        st.info("Generate a key pair first.")

# ---------------------------------------------------------------- (b) AUTH
with tabs[3]:
    st.subheader("(b) Authentication & authorization with JWT")
    l, r = st.columns(2)
    with l:
        with st.form("login"):
            u = st.selectbox("User", ["alice", "bob", "admin"]); pw = st.text_input("Password", type="password")
            ttl = st.slider("Token lifetime (seconds)", 5, 300, 120)
            if st.form_submit_button("Login"):
                rr = requests.post(f"{API}/login", json={"username": u, "password": pw, "ttl": ttl})
                if rr.ok: ss.token = rr.json()["token"]; st.success("Authenticated – JWT received")
                else: ss.token = None; st.error(rr.json()["error"])
        if ss.token:
            st.markdown("**JWT (header.payload.signature)**"); st.code(ss.token, language="text")
            st.json({"header": jwt.get_unverified_header(ss.token), "payload": jwt.decode(ss.token, options={"verify_signature": False})})
            if st.button("😈 Forge token: change role to admin (keep old signature)"):
                h, p, s = ss.token.split(".")
                pl = json.loads(base64.urlsafe_b64decode(p + "=="))
                pl["role"] = "admin"
                p2 = base64.urlsafe_b64encode(json.dumps(pl).encode()).rstrip(b"=").decode()
                ss.token = f"{h}.{p2}.{s}"; st.warning("Payload modified – call an endpoint to see it rejected")
    with r:
        st.markdown("**Call secured API endpoints**")
        for label, m, p in [("GET /profile (any logged-in user)", "GET", "/profile"),
                            ("GET /admin/users (admin only)", "GET", "/admin/users")]:
            if st.button(label):
                rr = call(m, p); (st.success if rr.ok else st.error)(f"{rr.status_code}"); st.json(rr.json())
        if st.button("Call /profile WITHOUT token"):
            rr = requests.get(f"{API}/profile"); st.error(rr.status_code); st.json(rr.json())
        st.markdown("**Request log**"); st.code("\n".join(ss.log[:8]) or "—")

# ---------------------------------------------------------------- CASE STUDY
with tabs[4]:
    st.subheader("Case study: digital signatures in e-commerce and banking")
    st.markdown("""
**Problem.** Online payments cross untrusted networks. The bank/merchant must be sure of (1) **authenticity** – who sent the order,
(2) **integrity** – amount/payee were not changed, (3) **non-repudiation** – the customer cannot later deny it, and (4) freshness (no replay).

**How digital signatures solve it**
| Where used | What is signed | Benefit |
|---|---|---|
| **Internet banking / UPI / SWIFT** | Payment instruction (payee, amount, nonce, time) | Tampering with amount invalidates signature; audit-proof evidence |
| **TLS on e-commerce sites** | Server certificate signed by a CA (RSA/ECDSA) | Customer knows the shop is genuine, prevents phishing clones |
| **EMV chip cards / 3-D Secure** | Cryptogram over transaction data | Stops card cloning and altered-amount fraud |
| **Invoices, contracts, e-KYC (Aadhaar eSign, DSC)** | Document hash | Legally valid under the IT Act 2000 (India) / eIDAS (EU) |
| **Software & app updates / API webhooks** | Package hash | Users trust downloads and callbacks |

**Why hash-then-sign?** RSA signs a fixed-size digest (SHA-256) of the message, so any 1-bit change gives a different digest and the signature fails to verify.

**Limits & mitigations:** private-key theft (→ HSM, hardware tokens, key rotation), replay (→ nonce + timestamp, shown below),
weak keys (→ RSA ≥ 2048 or ECDSA), and the need for a trusted CA / PKI to bind a key to a real identity.
""")
    st.markdown("### 🧪 Live demo: signed bank transfer (uses the Flask API)")
    if not ss.token:
        st.info("Login as **alice** or **bob** in the previous tab first."); st.stop()
    who = jwt.decode(ss.token, options={"verify_signature": False})
    st.write(f"Logged in as **{who['sub']}** (role: {who['role']})")
    if st.button("1️⃣ Generate key & register public key with bank"):
        ss.tx_key = S.generate_keypair()
        rr = call("POST", "/keys", json={"public_key_pem": S.public_pem(ss.tx_key)}); st.json(rr.json())
    if ss.tx_key:
        c1, c2, c3 = st.columns(3)
        to = c1.selectbox("Pay to", [x for x in ("alice", "bob") if x != who["sub"]] or ["bob"])
        amt = c2.number_input("Amount", 1.0, 100000.0, 100.0)
        tamper = c3.checkbox("😈 Attacker changes amount after signing")
        if st.button("2️⃣ Sign & send transfer"):
            tx = {"from": who["sub"], "to": to, "amount": amt, "nonce": uuid.uuid4().hex}
            sig = base64.b64encode(S.sign(ss.tx_key, S.canonical(tx))).decode()
            sent = {**tx, "amount": amt * 10} if tamper else tx
            rr = call("POST", "/transfer", json={**sent, "signature": sig})
            (st.success if rr.ok else st.error)(f"{rr.status_code}: {rr.json().get('message') or rr.json().get('error')}")
            st.session_state.last_tx = {**sent, "signature": sig}
        if "last_tx" in ss and st.button("🔁 Replay the last request"):
            rr = call("POST", "/transfer", json=ss.last_tx); st.error(f"{rr.status_code}: {rr.json().get('error') or rr.json().get('message')}")
        if st.button("📊 My balance"):
            st.json(call("GET", "/profile").json())
