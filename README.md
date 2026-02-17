# 🛡️ AEGIS-1T: TERABYTE-SCALE MFA VAULT

Aegis-1T is a high-performance cryptographic utility designed to secure sensitive data ranging from 1-byte configuration files to **1TB+ databases**. It bridges the gap between massive data storage and physical multi-factor authentication (MFA).

---

## **🚀 KEY FEATURES**

* **⚡ Hybrid Streaming Engine**
    Custom-built to process massive files using a buffered I/O system. Maintains a constant RAM footprint of **<100MB** regardless of file size.
* **📱 Offline MFA Integration**
    Hardened security via Google Authenticator (TOTP). The vault remains cryptographically locked unless the 6-digit physical key is provided.
* **🔑 Argon2id Key Derivation**
    Implements the industry-leading **Argon2id** algorithm to ensure maximum resistance against GPU-accelerated brute-force attacks.
* **🔐 Authenticated Encryption**
    Utilizes **AES-256-GCM** to provide high-speed confidentiality and built-in integrity checking (tamper detection).
* **🧹 Secure Shredder**
    Includes a "Zero-Fill" protocol that overwrites data with null bytes (`0x00`) before deletion to prevent forensic recovery.

---

## **🛠️ TECHNICAL STACK**

| Component | Technology |
| :--- | :--- |
| **Core** | Python 3.12+ |
| **Encryption** | AES-256-GCM (`pycryptodome`) |
| **KDF** | Argon2id (`argon2-cffi`) |
| **MFA** | TOTP (`pyotp`, `qrcode`) |
| **Config** | `python-dotenv` |

---

🌐 DOWNLOADS & ENVIRONMENT
Before you begin, ensure your system is equipped with the following core technologies:
🐍 Python 3.12+
The engine is built on the latest Python standards for high-performance memory management.

🐙 Git SCM
Required for secure version control and cloning the repository.

📱 TOTP Authenticator
You will need a mobile app to generate the physical 2FA keys.

Google Authenticator | Aegis MFA


## **📦 INSTALLATION**

Set up your environment in seconds by running these commands:

---

```bash
# Clone the repository
git clone https://github.com/kiarash110/Aegis-1T.git
# Enter the directory
cd Aegis-1T

# Install security dependencies
pip install -r requirements.txt
