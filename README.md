# 🛡️ Aegis-1T: Terabyte-Scale MFA Vault

Aegis-1T is a high-performance cryptographic utility designed to secure sensitive data ranging from 1-byte configuration files to 1TB databases. It bridges the gap between massive data storage and physical multi-factor authentication (MFA).

## 🚀 Key Features
* **Hybrid Streaming Engine:** Custom-built to process 1TB+ files using a buffered I/O system, maintaining a constant RAM footprint of <100MB regardless of file size.
* **Offline MFA Integration:** Hardened security via Google Authenticator (TOTP). The vault remains locked unless the time-synced 6-digit physical key is provided.
* **Argon2id Key Derivation:** Implements the winning algorithm of the Password Hashing Competition to ensure maximum resistance against GPU-accelerated brute-force attacks.
* **Authenticated Encryption:** Uses **AES-256-GCM** to provide both confidentiality and built-in integrity checking (tamper detection).
* **Secure Shredder:** Features a 120-second "Self-Destruct" timer that memory-zeroes and shreds decrypted files to prevent forensic data recovery.

## 🛠️ Technical Stack
* **Core:** Python 3.12+
* **Cryptography:** `pycryptodome` (AES-GCM)
* **Key Stretching:** `argon2-cffi`
* **Authentication:** `pyotp`, `qrcode`

## 📋 Prerequisites
Before you begin, ensure you have the following installed:
* **Python 3.12+** - [Download Python](https://www.python.org/downloads/)
* **Git** - [Download Git](https://git-scm.com/downloads) (Required for cloning)
* **Smartphone** - With Google Authenticator or any TOTP app installed.

## 📦 Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/kiarash110/Aegis-1T.git](https://github.com/kiarash110/Aegis-1T.git)
   cd Aegis-1T
