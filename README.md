🛡️ Aegis-1T: Terabyte-Scale MFA Vault
Aegis-1T is a high-performance cryptographic utility designed to secure sensitive data ranging from 1-byte configuration files to 1TB+ databases. It bridges the gap between massive data storage and physical multi-factor authentication (MFA).

🚀 KEY FEATURES
⚡ Hybrid Streaming Engine
Custom-built to process massive files using a buffered I/O system. Maintains a constant RAM footprint of <100MB regardless of file size, ensuring stability on all hardware.

📱 Offline MFA Integration
Hardened security via Google Authenticator (TOTP). The vault remains cryptographically locked unless the time-synced 6-digit physical key is provided.

🔑 Argon2id Key Derivation
Implements the industry-leading Argon2id algorithm to ensure maximum resistance against GPU-accelerated brute-force and side-channel attacks.

🔐 Authenticated Encryption
Utilizes AES-256-GCM to provide both high-speed confidentiality and built-in integrity checking (tamper detection).

🧹 Secure Shredder
Includes a manual "Zero-Fill" shredding protocol that overwrites sensitive data with null bytes (0x00) before deletion to prevent forensic data recovery.

🛠️ TECHNICAL STACK
Core: Python 3.12+

Cryptography: pycryptodome (AES-GCM)

Key Stretching: argon2-cffi (Argon2id)

Authentication: pyotp, qrcode

Configuration: python-dotenv

📋 PREREQUISITES
Before you begin, ensure you have the following:

Python 3.12+ — Download here

Smartphone — Equipped with Google Authenticator, Aegis, or any TOTP-compatible app.

📦 INSTALLATION
1. Clone the repository:

Bash
git clone https://github.com/kiarash110/Aegis-1T.git
cd Aegis-1T
2. Install security dependencies:

Bash
pip install -r requirements.txt
🔐 SETUP & USAGE
1. Initialize MFA
Before using the vault, you must link your physical device to generate the unique identity secret:

Bash
python setup_mfa.py
Scan the generated mfa_setup.png with your phone.

⚠️ IMPORTANT: Delete the mfa_setup.png file immediately after scanning.

2. Operating the Vault
Run the main engine to encrypt or decrypt your data:

Bash
python aegis_vault.py
Action: Type E to Encrypt or D to Decrypt.

Path: Provide the full path to your file.

Password: Enter your master vault password.

🔍 TROUBLESHOOTING
❌ MFA "Invalid Code" Errors
If your 6-digit code is rejected:

Time Sync: TOTP relies on precision. Ensure both your phone and computer are set to "Set Time Automatically." A drift of even 30 seconds will cause a mismatch.

Duplicate Secrets: Check your .env file. Ensure there is only one MFA_SECRET line. If you re-run the setup, you must scan the new QR code.

📉 Memory & Performance
1TB Files: If performance dips on massive files, ensure your BUFFER_SIZE in the code is optimized for your specific drive's I/O speed.

Shredding: Secure shredding requires write permissions. If the shredder fails, run your terminal as an Administrator.
