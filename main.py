import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import time

# Simple in-memory data store
data_store = {}

# Generate a Fernet key
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Hash function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt function
def encrypt_data(data):
    return fernet.encrypt(data.encode()).decode()

# Decrypt function
def decrypt_data(token):
    return fernet.decrypt(token.encode()).decode()

# Track failed attempts
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0

# Sidebar Navigation
st.sidebar.title("🔐 Secure Data System")
page = st.sidebar.radio("🚀 Navigate", ["🏠 Home", "📝 Store Data", "🔓 Retrieve Data", "📁 View Stored", "🔑 Login"])

# Home
if page == "🏠 Home":
    st.markdown("## 🛡 Secure Data Encryption System")
    st.write("Welcome! This app allows you to securely *encrypt and store your data* using a unique passkey.")
    st.markdown("""
    - 🔒 *Encrypted* using Fernet encryption  
    - 🧠 *Passkeys* hashed with SHA-256  
    - ⏳ Option to auto-expire data  
    - ❌ Access is *blocked* after 3 failed attempts  
    """)
    st.info("📌 Use the sidebar to navigate.")

# Store Data
elif page == "📝 Store Data":
    st.header("📦 Store Encrypted Data")
    key = st.text_input("🔑 Enter Passkey", type="password")
    data = st.text_area("📝 Enter your data")
    expire = st.slider("⏲ Auto-expire in seconds (0 = never)", 0, 300, 0)

    if st.button("🔐 Encrypt & Store"):
        if key and data:
            hashed_key = hash_passkey(key)
            encrypted = encrypt_data(data)
            expiry_time = time.time() + expire if expire else None
            data_store[hashed_key] = {'data': encrypted, 'expiry': expiry_time}
            st.success("✅ Data stored securely!")
        else:
            st.warning("⚠ Please fill both fields.")

# Retrieve Data
elif page == "🔓 Retrieve Data":
    st.header("🔍 Retrieve Your Data")
    key = st.text_input("🔑 Enter Your Passkey", type="password")

    if st.button("🔎 Decrypt"):
        if st.session_state.attempts >= 3:
            st.error("🚫 Access Blocked! Too many failed attempts.")
        elif key:
            hashed_key = hash_passkey(key)
            record = data_store.get(hashed_key)

            if record:
                if record['expiry'] and time.time() > record['expiry']:
                    st.warning("⌛ This data has expired.")
                else:
                    decrypted = decrypt_data(record['data'])
                    st.success("✅ Data Retrieved Successfully!")
                    st.code(decrypted)
                    st.session_state.attempts = 0
            else:
                st.session_state.attempts += 1
                st.error("❌ Invalid Passkey!")

# View Stored Data (Demo purpose)
elif page == "📁 View Stored":
    st.header("🗃 Stored Data (Demo Only)")
    st.write(data_store)

# Login (optional page)
elif page == "🔑 Login":
    st.header("👤 Login Page (Demo Purpose)")
    st.write("You can add real authentication here if required.")