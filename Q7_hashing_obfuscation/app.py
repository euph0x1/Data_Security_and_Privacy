import contextlib, io
import streamlit as st
from hashing import ALGOS, hash_text, hash_file_stream, bit_diff
from obfuscator import obfuscate, deobfuscate_pack
from sample_code import SAMPLE

st.set_page_config(page_title="Q7 · Hashing & Obfuscation", page_icon="#️⃣", layout="wide")
st.title("#️⃣ Q7 · Hash Functions and Obfuscation")
tabs = st.tabs(["📐 Architecture", "🔢 (a) Hash functions", "🎭 (b) Obfuscation"])

# ---------------------------------------------------------------- ARCHITECTURE
with tabs[0]:
    st.subheader("System architecture")
    st.graphviz_chart('''
    digraph G { rankdir=LR; node [shape=box, style="rounded,filled", fontname=Helvetica, fillcolor="#e8f0fe"];
      U [label="User\\n(browser)", fillcolor="#fef7e0"];
      subgraph cluster_ui { label="Streamlit front-end (app.py)"; style=dashed;
        T1 [label="Hash tab\\ntext / file input"]; T2 [label="Obfuscation tab\\nsource editor + options"]; }
      subgraph cluster_core { label="Python back-end modules"; style=dashed;
        H [label="hashing.py\\nhashlib: MD5, SHA-1, SHA-256,\\nSHA-512, SHA3, BLAKE2", fillcolor="#e6f4ea"];
        O [label="obfuscator.py\\nast transformer:\\nstrip → rename → encode strings → pack", fillcolor="#e6f4ea"]; }
      R [label="Result\\ndigest / obfuscated code\\n+ run-comparison", fillcolor="#fce8e6"];
      U -> T1; U -> T2; T1 -> H; T2 -> O; H -> R; O -> R; R -> U [style=dashed]; }''')
    st.markdown("""
**(a) Hashing** – the front-end sends the text (UTF-8 bytes) or an uploaded file to `hashlib`. Files are hashed in 64 KB chunks with `update()`
so memory stays constant. Output is a fixed-length hex digest. Extra demos: *integrity check* (compare with a known hash) and the
*avalanche effect* (1 changed character flips ≈ 50 % of the output bits).

**(b) Obfuscation** – `obfuscator.py` parses the source into an **AST**, then applies transformations in a pipeline:
1. **Strip** docstrings/comments (removes human hints) 2. **Rename** variables/functions/arguments to meaningless `_0x…` names
3. **Encode string literals** (Base64, decoded at run-time) 4. **Pack** – compress+encode the whole program and run it via `exec()`.
The app then *executes both versions* to prove behaviour is unchanged, and shows how easily the packed layer is reversed.

| Concept | Hash | Obfuscation |
|---|---|---|
| Purpose | Integrity / fingerprint | Make code hard to read |
| Reversible? | No (one-way) | Yes, with effort (no key → not encryption) |
| Security value | Strong (SHA-256) | Only slows attackers down |
""")

# ---------------------------------------------------------------- HASHING
with tabs[1]:
    st.subheader("Compute hashes")
    algos = st.multiselect("Algorithms", ALGOS, default=["md5", "sha256", "sha512"])
    mode = st.radio("Input type", ["Text", "File"], horizontal=True)
    digests = {}
    if mode == "Text":
        text = st.text_area("Enter a string", "Hello, Cryptography!")
        digests = {a: hash_text(text, a) for a in algos}
    else:
        f = st.file_uploader("Upload any file")
        if f:
            for a in algos:
                f.seek(0); digests[a] = hash_file_stream(f, a)
    if digests:
        st.table({"Algorithm": [a.upper() for a in digests], "Bits": [len(v) * 4 for v in digests.values()], "Digest (hex)": list(digests.values())})
        st.warning("MD5 and SHA-1 are **broken for collision resistance** – use SHA-256 or better for security work.")
        st.markdown("#### ✅ Integrity check")
        expected = st.text_input("Paste an expected hash to compare").strip().lower()
        if expected:
            match = [a for a, d in digests.items() if d == expected]
            st.success(f"Match with {match[0].upper()} – data is intact") if match else st.error("No match – data changed or wrong algorithm")

    st.markdown("---\n#### 🌊 Avalanche effect (SHA-256)")
    c1, c2 = st.columns(2)
    m1 = c1.text_input("Message 1", "hello world"); m2 = c2.text_input("Message 2", "hello worle")
    h1, h2 = hash_text(m1, "sha256"), hash_text(m2, "sha256")
    c1.code(h1); c2.code(h2)
    d = bit_diff(h1, h2)
    st.metric("Bits that differ (of 256)", d, f"{d/256:.0%}")

# ---------------------------------------------------------------- OBFUSCATION
with tabs[2]:
    st.subheader("Hide a Python function's logic")
    o1, o2, o3, o4 = st.columns(4)
    strip = o1.checkbox("Strip docstrings", True); ren = o2.checkbox("Rename identifiers", True)
    strs = o3.checkbox("Encode strings", True); pack = o4.checkbox("Pack (zlib+base64 exec)", True)
    src = st.text_area("Original source code", SAMPLE, height=220)
    if st.button("🎭 Obfuscate", type="primary"):
        try:
            st.session_state.obf = (src, obfuscate(src, rename=ren, strings=strs, pack=pack, strip=strip))
        except SyntaxError as e:
            st.error(f"Syntax error in source: {e}")
    if "obf" in st.session_state:
        orig, obf = st.session_state.obf
        cA, cB = st.columns(2)
        cA.markdown("**Original**"); cA.code(orig, language="python")
        cB.markdown("**Obfuscated**"); cB.code(obf, language="python")
        st.caption(f"Size: {len(orig)} → {len(obf)} characters")

        def run(code):
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf): exec(code, {"__name__": "__demo__"})
            except Exception as e:
                buf.write(f"Error: {e}")
            return buf.getvalue()
        r1, r2 = run(orig), run(obf)
        cA.markdown("**Output**"); cA.code(r1 or "(no output)")
        cB.markdown("**Output**"); cB.code(r2 or "(no output)")
        st.success("Outputs identical – behaviour preserved ✅") if r1 == r2 else st.error("Outputs differ")
        if pack:
            with st.expander("🔓 Reverse the packing layer (proof that obfuscation ≠ encryption)"):
                st.code(deobfuscate_pack(obf), language="python")
    st.markdown("""
#### Techniques explored
| Technique | Example | Weakness |
|---|---|---|
| Renaming | `calculate_discount` → `_0x00645` | Logic still readable |
| String encoding | `"vip"` → `b64decode('dmlw')` | Decode with one line |
| Packing / `exec` | zlib+Base64 blob | Print instead of exec |
| Control-flow flattening, opaque predicates, bytecode-only (`.pyc`), Cython/PyArmor | *discussed, not implemented* | Cost/performance |
""")
