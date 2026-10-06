import json
import streamlit as st
from e2ee import Device, fingerprint
from relay_server import start_in_thread
from client import request
from diagrams import sequence_svg, show_svg

st.set_page_config(page_title="Q6 · Secure Messaging (TLS + E2EE)", page_icon="🔐", layout="wide")


@st.cache_resource
def get_server():
    return start_in_thread()          # real TLS server running in a background thread


server = get_server()

ss = st.session_state
if "dev" not in ss:
    ss.dev, ss.chat, ss.tls, ss.connected = {}, {"Alice": [], "Bob": []}, None, False

st.title("🔐 Q6 · Secure Real-Time Messaging — TLS + End-to-End Encryption")
tabs = st.tabs(["📐 Architecture", "🔁 Sequence diagram", "💬 Live demo", "🕵️ What the server sees"])

# ------------------------------------------------------------------ ARCHITECTURE
with tabs[0]:
    st.subheader("System architecture")
    st.graphviz_chart('''
    digraph G { rankdir=LR; node [shape=box, style="rounded,filled", fontname=Helvetica];
      subgraph cluster_a { label="Device A (Alice)"; style=dashed;
        A_UI [label="Chat UI", fillcolor="#e8f0fe"];
        A_K  [label="X25519 key pair\\n(private key stays here)", fillcolor="#fce8e6"];
        A_C  [label="HKDF + AES-256-GCM\\nencrypt / decrypt", fillcolor="#e6f4ea"];
        A_UI -> A_C; A_K -> A_C; }
      subgraph cluster_s { label="Relay Server (untrusted)"; style=dashed;
        S_T [label="TLS 1.2/1.3 endpoint", fillcolor="#e8f0fe"];
        S_D [label="Public-key directory\\n+ ciphertext mailbox", fillcolor="#fef7e0"];
        S_T -> S_D; }
      subgraph cluster_b { label="Device B (Bob)"; style=dashed;
        B_UI [label="Chat UI", fillcolor="#e8f0fe"];
        B_K  [label="X25519 key pair\\n(private key stays here)", fillcolor="#fce8e6"];
        B_C  [label="HKDF + AES-256-GCM\\nencrypt / decrypt", fillcolor="#e6f4ea"];
        B_UI -> B_C; B_K -> B_C; }
      A_C -> S_T [label=" TLS tunnel: E2EE ciphertext ", color="#1a73e8"];
      S_T -> B_C [label=" TLS tunnel: E2EE ciphertext ", color="#1a73e8"];
    }''')
    st.markdown("""
### How the system works
| Layer | Technology | Protects against | Who can read the data? |
|---|---|---|---|
| **Transport** | TLS 1.2/1.3 (Python `ssl`, self-signed cert, verified by client) | Eavesdroppers / tampering on the network, fake servers | Client ⇄ server endpoints |
| **End-to-end** | X25519 (ECDH) → HKDF-SHA256 → AES-256-GCM | A curious / hacked / subpoenaed **server** | **Only sender and recipient** |

**Components**
1. **Device (`e2ee.py`)** – generates an X25519 key pair. The *private key never leaves the device*. Derives a shared secret with the peer's public key (ECDH), stretches it with HKDF into a 256-bit AES key, and encrypts each message with AES-GCM (random 96-bit nonce; sender→recipient string is authenticated as AAD).
2. **Relay server (`relay_server.py`)** – a TLS socket server that (a) stores each user's **public** key, (b) queues opaque `{from, to, nonce, ciphertext}` frames, (c) hands them over on `fetch`. It has no private keys, so it *cannot* decrypt – it is purely a relay.
3. **Client (`client.py`)** – opens a TLS connection, validates the server certificate, then sends JSON frames.
4. **Safety number** – hash of both public keys shown to both users; comparing it out-of-band (call/in person) defeats a malicious server that swaps public keys (man-in-the-middle).

**Security properties:** confidentiality (AES-GCM), integrity/authenticity of each message (GCM tag – any tampering fails decryption), server blindness (no key material), forward-secrecy would be added by ratcheting (Signal Double Ratchet – out of scope, listed as an extension).
""")

# ------------------------------------------------------------------ SEQUENCE
with tabs[1]:
    st.subheader("Sequence diagram – secure message from Alice to Bob")
    P = ["Alice (Device A)", "Relay Server", "Bob (Device B)"]
    steps = [
        (0, 0, "1. Generate X25519 key pair", "e2ee"),
        (2, 2, "1. Generate X25519 key pair", "e2ee"),
        (0, 1, "2. TLS handshake + verify certificate", "tls"),
        (0, 1, "3. register(Alice, pubA)  [over TLS]", "tls"),
        (2, 1, "4. TLS handshake + register(Bob, pubB)", "tls"),
        (0, 1, "5. get_key(Bob)  [over TLS]", "tls"),
        (1, 0, "6. pubB", "tls", True),
        (0, 0, "7. ECDH(privA,pubB) → HKDF → key K", "e2ee"),
        (0, 0, "8. AES-GCM(K, nonce, plaintext)", "e2ee"),
        (0, 1, "9. send{to:Bob, nonce, ciphertext}", "tls"),
        (1, 1, "10. Store ciphertext (cannot decrypt)", "err"),
        (2, 1, "11. fetch(Bob)  [over TLS]", "tls"),
        (1, 2, "12. {from:Alice, nonce, ciphertext}", "tls", True),
        (2, 2, "13. ECDH(privB,pubA) → same K", "e2ee"),
        (2, 2, "14. AES-GCM decrypt → plaintext", "e2ee"),
    ]
    svg, h = sequence_svg(P, steps, col_w=330)
    show_svg(svg)
    st.caption("🔵 blue = protected by TLS   🟢 green = local crypto on a device   🔴 red = server-side (sees only ciphertext)")
    st.markdown("""**Reading the diagram:** Steps 1–5 are setup. Steps 7–8 & 13–14 happen only on the devices. Steps 9 and 12
travel through TLS *and* carry ciphertext, so an attacker needs to break **both** layers. The server in step 10 stores bytes it cannot interpret.""")

# ------------------------------------------------------------------ SERVER VIEW
with tabs[3]:
    st.subheader("Server-side log – everything the relay ever saw")
    st.caption("This is the raw data the server received. Look for plaintext – there is none.")
    if st.button("🔄 Refresh log"):
        pass
    st.write("**Public-key directory:**", {k: v[:16] + "…" for k, v in server.state.keys.items()})
    for e in reversed(server.state.log[-20:]):
        st.code(json.dumps(e, indent=1), language="json")

# ------------------------------------------------------------------ LIVE DEMO
with tabs[2]:
    st.subheader("Two devices talking through the real TLS relay")
    c1, c2 = st.columns([1, 3])
    if c1.button("🔌 Connect both devices", type="primary"):
        for n in ("Alice", "Bob"):
            ss.dev[n] = Device(n)
            r, ss.tls = request({"type": "register", "id": n, "pubkey": ss.dev[n].public_hex})
        ss.connected, ss.chat = True, {"Alice": [], "Bob": []}
    if not ss.connected:
        st.info("Click **Connect both devices**: each device generates its key pair, opens a TLS connection and registers its *public* key.")
        st.stop()

    c2.success(f"Connected via **{ss.tls['tls_version']}**, cipher **{ss.tls['cipher']}**")
    a, b = ss.dev["Alice"], ss.dev["Bob"]
    st.markdown(f"**Safety number** (both devices must show the same): `{fingerprint(a.public_hex, b.public_hex)}`")
    tamper = st.checkbox("😈 Simulate a malicious server tampering with the ciphertext")

    def send(frm, to, text):
        r, _ = request({"type": "get_key", "id": to})
        frame = ss.dev[frm].encrypt(to, r["pubkey"], text)
        if tamper:
            frame["ct"] = "A" + frame["ct"][1:] if frame["ct"][0] != "A" else "B" + frame["ct"][1:]
        request({"type": "send", **frame})
        ss.chat[frm].append(("me", text))

    def receive(me):
        r, _ = request({"type": "fetch", "id": me})
        for m in r["messages"]:
            k, _ = request({"type": "get_key", "id": m["from"]})
            try:
                ss.chat[me].append(("them", ss.dev[me].decrypt(m, k["pubkey"])))
            except Exception:
                ss.chat[me].append(("bad", "⚠️ Decryption FAILED – message was modified in transit (GCM tag mismatch)"))

    for col, me, other in zip(st.columns(2), ("Alice", "Bob"), ("Bob", "Alice")):
        with col:
            st.markdown(f"### 📱 {me}'s device")
            st.caption(f"public key: `{ss.dev[me].public_hex[:24]}…`")
            with st.form(f"f_{me}", clear_on_submit=True):
                txt = st.text_input(f"Message to {other}", key=f"t_{me}")
                if st.form_submit_button("Send 🔒") and txt:
                    send(me, other, txt)
            if st.button(f"📥 Check {me}'s inbox", key=f"r_{me}"):
                receive(me)
            for who, msg in ss.chat[me]:
                if who == "bad":
                    st.error(msg)
                else:
                    st.chat_message("user" if who == "me" else "assistant").write(msg)
