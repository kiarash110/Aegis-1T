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

## **🌐 DOWNLOADS & ENVIRONMENT**

## **🐍 [PYTHON 3.12+](https://www.python.org/downloads/)**
> **The engine is built on the latest Python standards for high-performance memory management and cryptographic stability.**

## **🐙 [GIT SCM](https://git-scm.com/downloads)**
> **Required for secure version control, repository management, and cloning the Aegis-1T source code.**

## **📱 TOTP AUTHENTICATOR**
## **🔐 REQUIRED: PHYSICAL SECOND FACTOR**
>You MUST have a mobile application installed to generate the physical 6-digit 2FA security keys required to unlock the vault.

## **✅ [GOOGLE AUTHENTICATOR](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2) — INDUSTRY STANDARD**
## **🍎 [GOOGLE AUTHENTICATOR (IOS/IPHONE)](https://apps.apple.com/us/app/google-authenticator/id388497605)**
---

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

```
---

## **⚖️ LEGAL DISCLAIMER**

**Aegis-1T is an independent, open-source educational project. It is NOT affiliated with, endorsed by, or associated with the "Aegis Authenticator" app, Aegis Cyber Security, or any other existing "Aegis" trademarks. The name is used in its classical sense, referring to the mythological shield of protection.**

**⚠️ WARNING: Use this software at your own risk. The author is not responsible for any data loss, forgotten passwords, or lost MFA secrets. Always keep a physical backup of your master key.**

 
