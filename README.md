🛡️ Aegis-1T: Terabyte-Scale MFA Vault
Aegis-1T is a high-performance cryptographic utility designed to secure sensitive data ranging from 1-byte configuration files to 1TB databases. It bridges the gap between massive data storage and physical multi-factor authentication (MFA).

🚀 Key Features
Hybrid Streaming Engine: Custom-built to process 1TB+ files using a buffered I/O system, maintaining a constant RAM footprint of <100MB regardless of file size.

Offline MFA Integration: Hardened security via Google Authenticator (TOTP). The vault remains locked unless the time-synced 6-digit physical key is provided.

Argon2id Key Derivation: Implements the winning algorithm of the Password Hashing Competition (Argon2id) to ensure maximum resistance against GPU-accelerated brute-force attacks.

Authenticated Encryption: Uses AES-256-GCM to provide both confidentiality and built-in integrity checking (tamper detection).

Secure Shredder: Includes a manual "Zero-Fill" shredding protocol that overwrites sensitive files with null bytes (0x00) before deletion to prevent forensic data recovery.

🛠️ Technical Stack
Core: Python 3.12+

Cryptography: pycryptodome (AES-GCM)

Key Stretching: argon2-cffi (Argon2id)

Authentication: pyotp, qrcode

Configuration: python-dotenv

📋 Prerequisites
Before you begin, ensure you have the following:

Python 3.12+ - Download Python

Smartphone - With Google Authenticator, Aegis, or any TOTP app installed.

📦 Installation
Clone the repository:

Bash
git clone https://github.com/kiarash110/Aegis-1T.git
cd Aegis-1T
Install the security dependencies:

Bash
pip install -r requirements.txt
🔐 Setup & Usage
1. Initialize MFA
Before using the vault, you must link your physical device:

Bash
python setup_mfa.py
Scan the generated mfa_setup.png with your phone.

Important: Delete the mfa_setup.png file immediately after scanning.

2. Operating the Vault
Run the main engine to encrypt or decrypt files:

Bash
python aegis_vault.py
Follow the on-screen prompts to select your action (Encrypt/Decrypt), provide the file path, and enter your vault password.

🔍 Troubleshooting
1. MFA "Invalid Code" Errors
If your 6-digit code is rejected:

Time Sync: TOTP relies on precision. Ensure both your phone and computer are set to "Set Time Automatically." A drift of even 30 seconds will cause a mismatch.

Duplicate Secrets: Check your .env file. Ensure there is only one MFA_SECRET line. If you re-run setup_mfa.py, you must scan the new QR code.

2. Memory & Performance
1TB Files: The vault is designed for massive data. If performance dips, ensure your BUFFER_SIZE is optimized for your drive's I/O speed.

Shredding: Secure shredding requires write permissions. If shredding fails, run your terminal as an Administrator.
