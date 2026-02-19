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

* *🏎️ The system now features Nitro Mode for 1TB+ file transfers.*

* *🟢 Standard Mode: 16MB Buffer | Recommended for 4GB RAM systems. 🧱*

* *🟡 Extreme Mode: 512MB Buffer | Recommended for 8GB RAM systems. ⚡*

* *🔴 NITRO Mode: 1.5GB Buffer | Requires 16GB+ RAM. Do not use on low-end hardware. 🔥*
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

## **🔍 TROUBLESHOOTING**
## **❌ 1. MFA "INVALID CODE" ERRORS**
## **🕒 ACTION: SYNCHRONIZE YOUR SYSTEM CLOCK**
>TOTP (2FA) codes are mathematically generated based on time. If your computer and phone are off by even 30 seconds, the code will fail. Ensure both devices are set to "Set Time Automatically" in your system settings.

## **📂 2. ACCESS DENIED / PERMISSION ERRORS**
## **🔑 ACTION: ELEVATE USER PRIVILEGES**
>Encryption requires direct write access to your disk. If you are processing files in protected directories, run your terminal as an Administrator (Windows) or use sudo (Linux/Mac).

## **📉 3. PERFORMANCE & HANGING**
## **⚡ ACTION: HARDWARE SPEED LIMITATIONS**
>When processing 1TB+ datasets, speed is limited by your hardware (HDD vs. SSD). If the progress bar appears "stuck," the engine is waiting for your disk to catch up. DO NOT close the terminal or you may corrupt the file.

## **✅ THE FINAL SECURITY CHECKLIST**
## **🛡️ 1. CONFIGURE YOUR .GITIGNORE**
```To prevent accidental leakage of your private keys to the public web, ensure your .gitignore file contains these exact lines:
.env
mfa_setup.png
__pycache__/
*.pyc
```
## **📦 2. VERIFY YOUR REQUIREMENTS.TXT**
Ensure your environment has every cryptographic library needed to run the Aegis engine:
```
pycryptodome
argon2-cffi
pyotp
qrcode
python-dotenv
pillow
maskpass
psutil
```
## **📱 3. CRITICAL: SCAN & DESTROY**
## *STEP 1: Scan the mfa_setup.png into your mobile app.*
## *STEP 2: DELETE THE PNG FILE FROM YOUR DISK IMMEDIATELY.*
## *STEP 3: Never store a digital copy of your QR code on any device connected to the internet.*
## *Anti-Corruption: The script will automatically block encryption of any file ending in .aegis. This prevents double-encryption which can lead to permanent data loss.*

---

## **⚖️ LEGAL DISCLAIMER**

**Aegis-1T is an independent, open-source educational project. It is NOT affiliated with, endorsed by, or associated with the "Aegis Authenticator" app, Aegis Cyber Security, or any other existing "Aegis" trademarks. The name is used in its classical sense, referring to the mythological shield of protection.**

**⚠️ WARNING: Use this software at your own risk. The author is not responsible for any data loss, forgotten passwords, or lost MFA secrets. Always keep a physical backup of your master key.**

 
