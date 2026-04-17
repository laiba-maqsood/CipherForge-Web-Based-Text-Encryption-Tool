"""
app.py  —  Web-Based Text Encryption Tool
Tech Stack: Python · Streamlit · PyCryptodome
Author: Crypto Tool Project
"""

import streamlit as st
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from encryption_engine import (
    caesar_encrypt, caesar_decrypt,
    base64_encrypt, base64_decrypt,
    aes_encrypt, aes_decrypt,
    des_encrypt, des_decrypt,
    rsa_generate_keypair, rsa_encrypt, rsa_decrypt,
    vigenere_encrypt, vigenere_decrypt,
    autokey_vigenere_encrypt, autokey_vigenere_decrypt,
    vernam_encrypt, vernam_decrypt,
    otp_encrypt, otp_decrypt,
    transposition_encrypt, transposition_decrypt,
    rail_fence_encrypt, rail_fence_decrypt,
    hash_text,
    register_user, login_user, save_message, get_messages
)

# ──────────────────────────────────────────────────────────────
#  PAGE CONFIG & CUSTOM CSS
# ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherForge — Text Encryption Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
/* ── Google Fonts ── */
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap');

/* ── Root palette — Light & Airy ── */
:root {
    --bg:        #f0f4f8;
    --surface:   #ffffff;
    --surface2:  #e8edf5;
    --accent:    #0ea5e9;
    --accent2:   #6366f1;
    --accent3:   #10b981;
    --danger:    #f43f5e;
    --text:      #1e293b;
    --muted:     #64748b;
    --border:    rgba(99,102,241,0.18);
    --shadow:    0 2px 12px rgba(30,41,59,0.08);
}

/* ── Global reset ── */
html, body, [data-testid="stAppViewContainer"] {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'Syne', sans-serif;
}

[data-testid="stSidebar"] {
    background: var(--surface) !important;
    border-right: 1px solid var(--border);
    box-shadow: 2px 0 12px rgba(30,41,59,0.06);
}

/* ── Header ── */
.hero-header {
    text-align: center;
    padding: 2rem 0 1.2rem;
}
.hero-title {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 2.8rem;
    background: linear-gradient(135deg, #0ea5e9, #6366f1, #10b981);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -1px;
    margin: 0;
}
.hero-sub {
    font-family: 'Space Mono', monospace;
    color: var(--muted);
    font-size: 0.75rem;
    margin-top: 0.4rem;
    letter-spacing: 2px;
    text-transform: uppercase;
}

/* ── Cards ── */
.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.6rem;
    margin-bottom: 1.2rem;
    box-shadow: var(--shadow);
}
.card-title {
    font-family: 'Space Mono', monospace;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--accent2);
    margin-bottom: 0.8rem;
    font-weight: 700;
}

/* ── Result box ── */
.result-box {
    background: #f8faff;
    border: 1.5px solid var(--accent);
    border-radius: 10px;
    padding: 1.2rem;
    font-family: 'Space Mono', monospace;
    font-size: 0.82rem;
    word-break: break-all;
    color: #0369a1;
    line-height: 1.6;
}
.hash-box {
    border-color: var(--accent2);
    color: #4f46e5;
    background: #f5f3ff;
}
.key-box {
    border-color: #f59e0b;
    color: #b45309;
    background: #fffbeb;
    font-size: 0.72rem;
}

/* ── Algo badge ── */
.algo-badge {
    display: inline-block;
    background: linear-gradient(90deg, var(--accent2), var(--accent));
    color: #fff;
    font-family: 'Space Mono', monospace;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 3px 12px;
    border-radius: 99px;
    margin-bottom: 0.8rem;
    text-transform: uppercase;
}

/* ── Pills ── */
.pill {
    display: inline-block;
    background: #ede9fe;
    border: 1px solid #c4b5fd;
    border-radius: 99px;
    padding: 3px 12px;
    font-size: 0.7rem;
    font-family: 'Space Mono', monospace;
    color: #5b21b6;
    margin-top: 0.5rem;
}

/* ── Streamlit widget overrides ── */
.stTextArea textarea, .stTextInput input {
    background: #f8faff !important;
    border: 1.5px solid #cbd5e1 !important;
    color: var(--text) !important;
    font-family: 'Space Mono', monospace !important;
    border-radius: 10px !important;
}
.stTextArea textarea:focus, .stTextInput input:focus {
    border-color: var(--accent2) !important;
    box-shadow: 0 0 0 3px rgba(99,102,241,0.12) !important;
}
.stSelectbox > div > div {
    background: #f8faff !important;
    border: 1.5px solid #cbd5e1 !important;
    color: var(--text) !important;
    border-radius: 10px !important;
}
.stButton > button {
    background: linear-gradient(135deg, var(--accent2), var(--accent)) !important;
    color: #fff !important;
    font-family: 'Space Mono', monospace !important;
    font-weight: 700 !important;
    font-size: 0.8rem !important;
    letter-spacing: 1px !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 0.6rem 1.4rem !important;
    transition: opacity 0.2s, transform 0.1s !important;
    box-shadow: 0 2px 8px rgba(99,102,241,0.25) !important;
}
.stButton > button:hover {
    opacity: 0.88 !important;
    transform: translateY(-1px) !important;
}
div[data-testid="stNumberInput"] input {
    background: #f8faff !important;
    border: 1.5px solid #cbd5e1 !important;
    color: var(--text) !important;
    border-radius: 10px !important;
}

/* ── Radio buttons ── */
.stRadio > div {
    background: var(--surface2) !important;
    border-radius: 10px !important;
    padding: 0.4rem !important;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--surface2) !important;
    border-radius: 12px;
    padding: 4px;
    gap: 4px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: var(--muted) !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.75rem !important;
    border-radius: 8px !important;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, var(--accent2), var(--accent)) !important;
    color: #fff !important;
}

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    padding: 1rem !important;
    box-shadow: var(--shadow);
}
[data-testid="stMetricValue"] { color: var(--accent2) !important; }

/* ── Alerts ── */
.stSuccess { background: #f0fdf4 !important; border-color: var(--accent3) !important; color: #166534 !important; }
.stError   { background: #fff1f2 !important; border-color: var(--danger) !important; color: #9f1239 !important; }
.stWarning { background: #fffbeb !important; border-color: #f59e0b !important; color: #92400e !important; }
.stInfo    { background: #f0f9ff !important; border-color: var(--accent) !important; color: #0c4a6e !important; }

/* ── Expander ── */
.streamlit-expanderHeader {
    background: var(--surface2) !important;
    border-radius: 10px !important;
    color: var(--text) !important;
    font-family: 'Space Mono', monospace !important;
}

/* ── Divider ── */
hr { border-color: #e2e8f0 !important; margin: 1.5rem 0 !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: #c4b5fd; border-radius: 99px; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────
#  SESSION STATE INIT
# ──────────────────────────────────────────────────────────────
for key, default in {
    "logged_in": False,
    "username": "",
    "rsa_private": "",
    "rsa_public": "",
    "last_result": {},
    "last_key": "",
    "operation": "Encrypt",
    "page": "main",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ──────────────────────────────────────────────────────────────
#  SIDEBAR — Auth & Navigation
# ──────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 1rem 0 1.5rem;">
        <div style="font-size:2.5rem;">🔐</div>
        <div style="font-family:'Space Mono',monospace; font-size:0.65rem;
                    letter-spacing:3px; text-transform:uppercase; color:#64748b;">
            CipherForge v1.0
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Auth section ──
    st.markdown("### 🔑 Account")
    if st.session_state.logged_in:
        st.success(f"Signed in as **{st.session_state.username}**")
        if st.button("Sign Out", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.rerun()
    else:
        auth_tab = st.radio("", ["Login", "Register"], horizontal=True, label_visibility="collapsed")
        uname = st.text_input("Username", key="auth_user", placeholder="your_username")
        pwd   = st.text_input("Password", type="password", key="auth_pwd", placeholder="••••••••")

        if auth_tab == "Login":
            if st.button("Login", use_container_width=True):
                if not uname or not pwd:
                    st.error("Fill in both fields.")
                elif login_user(uname, pwd):
                    st.session_state.logged_in = True
                    st.session_state.username = uname
                    st.success("Welcome back!")
                    st.rerun()
                else:
                    st.error("Invalid credentials.")
        else:
            if st.button("Create Account", use_container_width=True):
                if not uname or not pwd:
                    st.error("Fill in both fields.")
                elif len(pwd) < 6:
                    st.warning("Password must be ≥ 6 characters.")
                elif register_user(uname, pwd):
                    st.success("Account created! Please login.")
                else:
                    st.error("Username already taken.")

    st.markdown("---")

    # ── Navigation ──
    st.markdown("### 🧭 Navigate")
    pages = {
        "🔒 Encrypt / Decrypt": "main",
        "#️⃣  Hashing":           "hash",
        "📚 My Vault":           "vault",
        "📖 Algorithm Guide":    "guide",
    }
    for label, page_id in pages.items():
        active = st.session_state.page == page_id
        if st.button(label, use_container_width=True,
                     type="primary" if active else "secondary"):
            st.session_state.page = page_id
            st.rerun()

    st.markdown("---")
    st.markdown("""
    <div style="font-family:'Space Mono',monospace;font-size:0.62rem;
                color:#334155;text-align:center;line-height:1.8;">
        AES-256 · DES · RSA-2048<br>Vigenère · Vernam · OTP<br>Transposition · Rail Fence<br>SHA-256/512 · MD5
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────
#  HERO HEADER
# ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="hero-header">
    <h1 class="hero-title">🔐 CipherForge</h1>
    <p class="hero-sub">Web-Based Text Encryption Tool · Python · Streamlit · PyCryptodome</p>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  PAGE: MAIN — Encrypt / Decrypt
# ─────────────────────────────────────────────────────────────
if st.session_state.page == "main":

    col_left, col_right = st.columns([1, 1], gap="large")

    # ── LEFT: Input ──
    with col_left:
        st.markdown('<div class="card"><div class="card-title">⚙️ Configuration</div>', unsafe_allow_html=True)

        operation = st.radio(
            "Operation",
            ["🔒 Encrypt", "🔓 Decrypt"],
            horizontal=True,
            key="op_radio"
        )
        is_encrypt = operation == "🔒 Encrypt"

        algorithm = st.selectbox(
            "Algorithm",
            [
                "── Classical ──",
                "Caesar Cipher",
                "Vigenère Cipher",
                "Autokey Vigenère Cipher",
                "Vernam Cipher",
                "One-Time Pad (OTP)",
                "Columnar Transposition",
                "Rail Fence Cipher",
                "Base64",
                "── Modern ──",
                "AES-256-CBC",
                "DES-CBC",
                "RSA-2048",
            ],
            help="Choose an encryption algorithm"
        )
        # Skip separator selections
        if algorithm.startswith("──"):
            st.warning("Please select an actual algorithm, not a section header.")
            st.stop()

        plain_text = st.text_area(
            "Input Text",
            height=160,
            placeholder="Enter text to encrypt or decrypt…",
            key="plain_input"
        )

        # ── Algorithm-specific options ──
        extra_key = ""
        shift_val = 13
        rail_count = 3
        keyword = ""

        if algorithm == "Caesar Cipher":
            shift_val = st.slider("Shift value (key)", 1, 25, 13)

        elif algorithm in ("Vigenère Cipher", "Autokey Vigenère Cipher", "Columnar Transposition"):
            keyword = st.text_input(
                "Keyword (letters only)",
                placeholder="e.g. SECRET",
                key="keyword_input"
            )
            if not is_encrypt:
                pass  # keyword doubles as decrypt key

        elif algorithm == "Vernam Cipher":
            if is_encrypt:
                vernam_key_mode = st.radio(
                    "Key mode",
                    ["🎲 Auto-generate key", "✏️ Enter my own key"],
                    horizontal=True,
                    key="vernam_key_mode"
                )
                if vernam_key_mode == "✏️ Enter my own key":
                    extra_key = st.text_input(
                        "Manual Key (letters A-Z, length ≥ number of letters in your text)",
                        placeholder="e.g. SECRETKEY",
                        key="vernam_manual_key"
                    )
                    st.caption("⚠️ Key must be letters only, at least as long as the letters in your plaintext.")
                else:
                    extra_key = ""
                    st.info("🎲 A cryptographically random key will be auto-generated. **Copy and save the key** shown after encryption — you need it to decrypt.")
            else:
                extra_key = st.text_input(
                    "Vernam Key (letters A-Z, same key used during encryption)",
                    placeholder="e.g. SECRETKEY",
                    key="vernam_key"
                )
                st.caption("ℹ️ Enter the exact key that was shown when you encrypted.")

        elif algorithm == "One-Time Pad (OTP)":
            if not is_encrypt:
                extra_key = st.text_input(
                    "OTP Key (Base64)",
                    placeholder="Paste the key from encryption step…",
                    key="otp_key"
                )
            else:
                st.info("🔐 OTP generates a perfectly random key equal to the plaintext length — theoretically unbreakable!")

        elif algorithm == "Rail Fence Cipher":
            rail_count = st.slider("Number of Rails (key)", 2, 10, 3)

        elif algorithm in ("AES-256-CBC", "DES-CBC"):
            if not is_encrypt:
                extra_key = st.text_input(
                    "Decryption Key (Base64)",
                    placeholder="Paste the key from encryption step…",
                    key="sym_key_input"
                )

        elif algorithm == "RSA-2048":
            st.info("RSA keypair is auto-generated per session. Generate or paste your own below.")
            gcol1, gcol2 = st.columns(2)
            with gcol1:
                if st.button("🔑 Generate Keypair", use_container_width=True):
                    priv, pub = rsa_generate_keypair()
                    st.session_state.rsa_private = priv
                    st.session_state.rsa_public  = pub
                    st.success("Keypair generated!")
            with gcol2:
                if st.session_state.rsa_private:
                    st.download_button(
                        "⬇ Private Key",
                        st.session_state.rsa_private,
                        file_name="private_key.pem",
                        mime="text/plain",
                        use_container_width=True
                    )

            if not is_encrypt:
                extra_key = st.text_area(
                    "Paste RSA Private Key (PEM)",
                    height=120,
                    placeholder="-----BEGIN RSA PRIVATE KEY-----\n...",
                    key="rsa_priv_input"
                )
            else:
                if st.session_state.rsa_public:
                    st.text_area(
                        "Public Key (auto-generated)",
                        value=st.session_state.rsa_public,
                        height=80,
                        disabled=True,
                        key="rsa_pub_display"
                    )
                else:
                    st.warning("Generate a keypair first!")

        st.markdown('</div>', unsafe_allow_html=True)

        # ── Save to vault option (if logged in) ──
        save_label = ""
        want_save = False
        if st.session_state.logged_in:
            st.markdown('<div class="card"><div class="card-title">💾 Vault</div>', unsafe_allow_html=True)
            want_save = st.checkbox("Save result to my vault", value=False)
            if want_save:
                save_label = st.text_input("Label / note", placeholder="e.g. My secret message")
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Action button ──
        btn_label = "🔒 Encrypt" if is_encrypt else "🔓 Decrypt"
        go = st.button(btn_label, use_container_width=True, type="primary")

    # ── RIGHT: Output ──
    with col_right:
        st.markdown('<div class="card"><div class="card-title">📤 Result</div>', unsafe_allow_html=True)

        if go:
            # ── Validation ──
            if not plain_text.strip():
                st.error("⚠️ Input text cannot be empty.")
                st.stop()

            try:
                result = {}
                key_used = ""

                if is_encrypt:
                    # ── ENCRYPTION ──
                    if algorithm == "Caesar Cipher":
                        result = caesar_encrypt(plain_text, shift_val)
                        key_used = str(shift_val)

                    elif algorithm == "Vigenère Cipher":
                        if not keyword:
                            st.error("Please enter a keyword.")
                            st.stop()
                        result = vigenere_encrypt(plain_text, keyword)
                        key_used = keyword.upper()

                    elif algorithm == "Autokey Vigenère Cipher":
                        if not keyword:
                            st.error("Please enter a keyword.")
                            st.stop()
                        result = autokey_vigenere_encrypt(plain_text, keyword)
                        key_used = keyword.upper()

                    elif algorithm == "Vernam Cipher":
                        # extra_key is "" for auto-mode, or the manual key string
                        result = vernam_encrypt(plain_text, extra_key)
                        key_used = result["key"]

                    elif algorithm == "One-Time Pad (OTP)":
                        result = otp_encrypt(plain_text)
                        key_used = result["key"]

                    elif algorithm == "Columnar Transposition":
                        if not keyword:
                            st.error("Please enter a keyword.")
                            st.stop()
                        result = transposition_encrypt(plain_text, keyword)
                        key_used = keyword.upper()

                    elif algorithm == "Rail Fence Cipher":
                        result = rail_fence_encrypt(plain_text, rail_count)
                        key_used = str(rail_count)

                    elif algorithm == "AES-256-CBC":
                        result = aes_encrypt(plain_text)
                        key_used = result["key"]

                    elif algorithm == "DES-CBC":
                        result = des_encrypt(plain_text)
                        key_used = result["key"]

                    elif algorithm == "RSA-2048":
                        if not st.session_state.rsa_public:
                            st.error("Generate a keypair first!")
                            st.stop()
                        result = rsa_encrypt(plain_text, st.session_state.rsa_public)
                        key_used = "See generated public key"

                    elif algorithm == "Base64":
                        result = base64_encrypt(plain_text)
                        key_used = "N/A"

                    output_text = result.get("ciphertext", "")
                    st.session_state.last_result = result
                    st.session_state.last_key = key_used

                    st.markdown(f'<div class="algo-badge">{result.get("algorithm", algorithm)}</div>', unsafe_allow_html=True)
                    st.markdown("**Ciphertext:**")
                    st.markdown(f'<div class="result-box">{output_text}</div>', unsafe_allow_html=True)
                    st.text_area("📋 Copy ciphertext", value=output_text, height=100, key="copy_cipher")

                    if key_used and key_used not in ("N/A", "See generated public key"):
                        if algorithm not in ("Caesar Cipher", "Rail Fence Cipher",
                                             "Vigenère Cipher", "Autokey Vigenère Cipher",
                                             "Columnar Transposition"):
                            st.markdown("**🔑 Encryption Key (keep safe!):**")
                            st.markdown(f'<div class="result-box key-box">{key_used}</div>', unsafe_allow_html=True)
                            st.text_area("📋 Copy key", value=key_used, height=60, key="copy_key")
                    if algorithm in ("Caesar Cipher", "Rail Fence Cipher"):
                        st.info(f"Key: **{key_used}** — remember this to decrypt!")
                    elif algorithm in ("Vigenère Cipher", "Autokey Vigenère Cipher", "Columnar Transposition"):
                        st.info(f"Keyword: **{key_used}** — use this to decrypt!")
                    elif algorithm == "Vernam Cipher":
                        st.warning(f"🔑 **Save this key to decrypt:** `{key_used}` — without it, the ciphertext cannot be recovered.")

                    # ── Save to vault ──
                    if want_save and save_label:
                        save_message(
                            st.session_state.username,
                            save_label, algorithm,
                            output_text, key_used
                        )
                        st.success("✅ Saved to your vault!")

                else:
                    # ── DECRYPTION ──
                    decrypted = ""

                    if algorithm == "Caesar Cipher":
                        decrypted = caesar_decrypt(plain_text, shift_val)

                    elif algorithm == "Vigenère Cipher":
                        if not keyword:
                            st.error("Please enter the keyword.")
                            st.stop()
                        decrypted = vigenere_decrypt(plain_text, keyword)

                    elif algorithm == "Autokey Vigenère Cipher":
                        if not keyword:
                            st.error("Please enter the keyword.")
                            st.stop()
                        decrypted = autokey_vigenere_decrypt(plain_text, keyword)

                    elif algorithm == "Vernam Cipher":
                        if not extra_key:
                            st.error("Please provide the Vernam key.")
                            st.stop()
                        decrypted = vernam_decrypt(plain_text, extra_key)

                    elif algorithm == "One-Time Pad (OTP)":
                        if not extra_key:
                            st.error("Please provide the OTP key (Base64).")
                            st.stop()
                        decrypted = otp_decrypt(plain_text, extra_key)

                    elif algorithm == "Columnar Transposition":
                        if not keyword:
                            st.error("Please enter the keyword.")
                            st.stop()
                        decrypted = transposition_decrypt(plain_text, keyword)

                    elif algorithm == "Rail Fence Cipher":
                        decrypted = rail_fence_decrypt(plain_text, rail_count)

                    elif algorithm == "AES-256-CBC":
                        if not extra_key:
                            st.error("Please provide the AES decryption key.")
                            st.stop()
                        decrypted = aes_decrypt(plain_text, extra_key)

                    elif algorithm == "DES-CBC":
                        if not extra_key:
                            st.error("Please provide the DES decryption key.")
                            st.stop()
                        decrypted = des_decrypt(plain_text, extra_key)

                    elif algorithm == "RSA-2048":
                        if not extra_key:
                            st.error("Please paste your RSA private key.")
                            st.stop()
                        decrypted = rsa_decrypt(plain_text, extra_key)

                    elif algorithm == "Base64":
                        decrypted = base64_decrypt(plain_text)

                    st.markdown(f'<div class="algo-badge">{algorithm} · Decrypted</div>', unsafe_allow_html=True)
                    st.markdown("**Plaintext:**")
                    st.markdown(f'<div class="result-box" style="color:#0f766e;background:#f0fdfa;border-color:#14b8a6;">{decrypted}</div>', unsafe_allow_html=True)
                    st.text_area("📋 Copy plaintext", value=decrypted, height=100, key="copy_plain")

                # ── Stats ──
                st.markdown("---")
                m1, m2, m3 = st.columns(3)
                m1.metric("Input Length",  f"{len(plain_text)} chars")
                if is_encrypt:
                    m2.metric("Output Length", f"{len(output_text)} chars")
                    m3.metric("Ratio", f"{len(output_text)/max(len(plain_text),1):.1f}×")
                else:
                    m2.metric("Decrypted Length", f"{len(decrypted)} chars")
                    m3.metric("Algorithm", algorithm.split("-")[0])

            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.info("Make sure you're using the correct key and that the input matches the expected format.")

        else:
            st.markdown("""
            <div style="text-align:center; padding:3rem 1rem; color:#94a3b8;">
                <div style="font-size:4rem; margin-bottom:1rem;">🛡️</div>
                <div style="font-family:'Space Mono',monospace; font-size:0.8rem; letter-spacing:2px; color:#64748b;">
                    READY TO CIPHER
                </div>
                <div style="margin-top:0.5rem; font-size:0.75rem; color:#475569;">
                    Enter text · Choose algorithm · Hit Encrypt
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  PAGE: HASHING
# ─────────────────────────────────────────────────────────────
elif st.session_state.page == "hash":
    st.markdown("## #️⃣ Cryptographic Hashing")
    st.info("Hashing is **one-way** — it cannot be reversed. Use it for integrity verification or password storage.")

    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.markdown('<div class="card"><div class="card-title">Input</div>', unsafe_allow_html=True)
        hash_input = st.text_area("Text to hash", height=160, placeholder="Enter any text…", key="hash_input")
        hash_algo  = st.selectbox("Hash Algorithm", ["SHA-256", "SHA-512", "MD5", "SHA-1"])
        do_hash    = st.button("# Compute Hash", use_container_width=True, type="primary")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="card"><div class="card-title">Hash Output</div>', unsafe_allow_html=True)
        if do_hash:
            if not hash_input.strip():
                st.error("Input cannot be empty.")
            else:
                r = hash_text(hash_input, hash_algo)
                st.markdown(f'<div class="algo-badge">{hash_algo}</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="result-box hash-box">{r["hash"]}</div>', unsafe_allow_html=True)
                st.text_area("📋 Copy hash", value=r["hash"], height=60, key="hash_copy")
                bits = {"SHA-256": 256, "SHA-512": 512, "MD5": 128, "SHA-1": 160}[hash_algo]
                hm1, hm2 = st.columns(2)
                hm1.metric("Output bits", f"{bits} bits")
                hm2.metric("Hex chars", f"{bits//4}")
                st.markdown('<div class="pill">⚠️ One-way — not reversible</div>', unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="text-align:center;padding:3rem 1rem;color:#94a3b8;">
                <div style="font-size:3rem;">#️⃣</div>
                <div style="font-family:'Space Mono',monospace;font-size:0.75rem;">
                    AWAITING INPUT
                </div>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  PAGE: VAULT
# ─────────────────────────────────────────────────────────────
elif st.session_state.page == "vault":
    st.markdown("## 📚 My Encrypted Vault")

    if not st.session_state.logged_in:
        st.warning("🔒 Please login from the sidebar to access your vault.")
    else:
        messages = get_messages(st.session_state.username)
        if not messages:
            st.info("Your vault is empty. Encrypt some text and save it here!")
        else:
            st.success(f"Found **{len(messages)}** saved message(s).")
            for i, msg in enumerate(messages):
                with st.expander(f"📨 {msg.get('label','Untitled')}  —  {msg.get('algorithm','?')}", expanded=False):
                    st.markdown(f'<div class="algo-badge">{msg.get("algorithm")}</div>', unsafe_allow_html=True)
                    st.markdown("**Ciphertext:**")
                    st.markdown(f'<div class="result-box">{msg.get("ciphertext","")}</div>', unsafe_allow_html=True)
                    st.text_area(f"Copy#{i}", value=msg.get("ciphertext",""), height=60, label_visibility="collapsed", key=f"vault_copy_{i}")
                    if msg.get("key") and msg["key"] not in ("N/A", ""):
                        st.markdown("**Key:**")
                        st.markdown(f'<div class="result-box key-box">{msg.get("key","")}</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
#  PAGE: ALGORITHM GUIDE
# ─────────────────────────────────────────────────────────────
elif st.session_state.page == "guide":
    st.markdown("## 📖 Algorithm Reference Guide")

    algos = [
        {
            "name": "Caesar Cipher",
            "type": "Symmetric · Classical Substitution",
            "icon": "🏛️",
            "desc": "One of the oldest encryption techniques. Each letter in the plaintext is shifted by a fixed number of positions in the alphabet.",
            "key_size": "1–25 (shift value)",
            "security": "⚠️ Very weak — easily brute-forced",
            "use_case": "Educational purposes only",
            "color": "#f59e0b",
        },
        {
            "name": "Vigenère Cipher",
            "type": "Symmetric · Polyalphabetic Substitution",
            "icon": "🔤",
            "desc": "Uses a keyword to apply multiple Caesar shifts cyclically. Each letter of the key shifts the corresponding plaintext letter by a different amount, hiding single-letter frequency patterns.",
            "key_size": "Keyword (any length)",
            "security": "⚠️ Weak — vulnerable to Kasiski/Friedman tests",
            "use_case": "Historical cryptography, educational",
            "color": "#f97316",
        },
        {
            "name": "Autokey Vigenère",
            "type": "Symmetric · Autokey Cipher",
            "icon": "🔁",
            "desc": "An improvement on Vigenère where the plaintext itself is appended to the keyword, eliminating key repetition. This defeats the Kasiski test but is still breakable with frequency analysis.",
            "key_size": "Short primer keyword",
            "security": "⚠️ Moderate — better than basic Vigenère",
            "use_case": "Historical cryptography, educational",
            "color": "#fb923c",
        },
        {
            "name": "Vernam Cipher",
            "type": "Symmetric · XOR Stream Cipher",
            "icon": "⊕",
            "desc": "XORs each character of plaintext with a corresponding key character. When the key is random, same-length, and used once, it becomes a One-Time Pad — the only mathematically proven unbreakable cipher.",
            "key_size": "Same length as plaintext",
            "security": "✅ Unbreakable if key is truly random & used once",
            "use_case": "Basis for OTP; secure comms",
            "color": "#00f5c4",
        },
        {
            "name": "One-Time Pad (OTP)",
            "type": "Symmetric · Perfect Secrecy",
            "icon": "🛡️",
            "desc": "A Vernam cipher with a truly random key. Proven by Claude Shannon to be perfectly secure — ciphertext reveals zero information about plaintext if the key is random, secret, and never reused.",
            "key_size": "Same length as plaintext (random)",
            "security": "✅ Mathematically unbreakable",
            "use_case": "Diplomatic hotlines, classified comms",
            "color": "#6366f1",
        },
        {
            "name": "Columnar Transposition",
            "type": "Symmetric · Transposition Cipher",
            "icon": "📊",
            "desc": "Rearranges the plaintext by writing it into a grid row-by-row, then reading columns off in an order determined by alphabetically sorting the keyword letters.",
            "key_size": "Keyword (determines column order)",
            "security": "⚠️ Weak alone; stronger when combined",
            "use_case": "Often combined with substitution ciphers",
            "color": "#a855f7",
        },
        {
            "name": "Rail Fence Cipher",
            "type": "Symmetric · Transposition Cipher",
            "icon": "🚂",
            "desc": "Writes plaintext in a zigzag pattern across a number of 'rails' (rows), then reads across each rail in order. Simple but easily broken by trying all rail counts.",
            "key_size": "Number of rails (2–10)",
            "security": "❌ Very weak — trivially brute-forced",
            "use_case": "Educational, introductory cryptography",
            "color": "#ec4899",
        },
        {
            "name": "Base64",
            "type": "Encoding (not encryption)",
            "icon": "📦",
            "desc": "Encodes binary data into ASCII characters. Not encryption — anyone can decode it. Useful for data transport.",
            "key_size": "None",
            "security": "❌ No security — trivially reversible",
            "use_case": "Data encoding, URL-safe transport",
            "color": "#94a3b8",
        },
        {
            "name": "DES-CBC",
            "type": "Symmetric · Block Cipher",
            "icon": "🔒",
            "desc": "Data Encryption Standard. 64-bit block cipher with 56-bit effective key length. Considered deprecated due to small key size.",
            "key_size": "64-bit (56-bit effective)",
            "security": "⚠️ Weak — vulnerable to brute force",
            "use_case": "Legacy systems only",
            "color": "#f97316",
        },
        {
            "name": "AES-256-CBC",
            "type": "Symmetric · Block Cipher",
            "icon": "🛡️",
            "desc": "Advanced Encryption Standard with 256-bit key. The gold standard for symmetric encryption, used by governments and military.",
            "key_size": "256-bit key + 128-bit IV",
            "security": "✅ Very strong — current gold standard",
            "use_case": "Secure data storage, VPNs, TLS",
            "color": "#00f5c4",
        },
        {
            "name": "RSA-2048",
            "type": "Asymmetric · Public Key",
            "icon": "🔑",
            "desc": "Public-key cryptography using two mathematically linked keys. Encrypt with public key, decrypt with private key. Based on prime factorization hardness.",
            "key_size": "2048-bit key pair",
            "security": "✅ Strong for key exchange",
            "use_case": "Key exchange, digital signatures, HTTPS",
            "color": "#6366f1",
        },
        {
            "name": "SHA-256",
            "type": "Cryptographic Hash",
            "icon": "#️⃣",
            "desc": "Secure Hash Algorithm producing a fixed 256-bit digest. One-way function — cannot be reversed. Used for integrity checking.",
            "key_size": "No key (one-way)",
            "security": "✅ Collision-resistant",
            "use_case": "Password hashing, file integrity, blockchain",
            "color": "#a855f7",
        },
    ]

    cols = st.columns(2)
    for i, algo in enumerate(algos):
        with cols[i % 2]:
            st.markdown(f"""
            <div class="card" style="border-color: {algo['color']}33;">
                <div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.8rem;">
                    <span style="font-size:1.6rem;">{algo['icon']}</span>
                    <div>
                        <div style="font-weight:800; font-family:'Syne',sans-serif; color:{algo['color']};">
                            {algo['name']}
                        </div>
                        <div style="font-family:'Space Mono',monospace; font-size:0.65rem;
                                    color:#64748b; text-transform:uppercase; letter-spacing:1px;">
                            {algo['type']}
                        </div>
                    </div>
                </div>
                <p style="font-size:0.83rem; color:#475569; line-height:1.6; margin-bottom:0.8rem;">
                    {algo['desc']}
                </p>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; font-size:0.72rem;
                            font-family:'Space Mono',monospace;">
                    <div style="background:#f1f5f9;padding:0.5rem;border-radius:8px;border:1px solid #e2e8f0;">
                        <div style="color:#94a3b8;font-size:0.65rem;">KEY SIZE</div>
                        <div style="color:{algo['color']};">{algo['key_size']}</div>
                    </div>
                    <div style="background:#f1f5f9;padding:0.5rem;border-radius:8px;border:1px solid #e2e8f0;">
                        <div style="color:#94a3b8;font-size:0.65rem;">USE CASE</div>
                        <div style="color:#334155;">{algo['use_case']}</div>
                    </div>
                </div>
                <div style="margin-top:0.6rem; font-family:'Space Mono',monospace; font-size:0.72rem;">
                    {algo['security']}
                </div>
            </div>
            """, unsafe_allow_html=True)
