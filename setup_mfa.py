import pyotp
import qrcode
import os
import json
import base64
import time
import sys
import maskpass  # Added for secure, hidden password input
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

# --- HIGH-SECURITY CONFIGURATION ---
MEM_COST = 204800  # 200MB 
TIME_COST = 4      
PARALLELISM = 4    
# -----------------------------------

def setup_aegis_vault():
    print("\n" + "="*55)
    print("🛡️  AEGIS-1T: SYSTEM INITIALIZATION (V1.0.2)")
    print("="*55)
    
    # 1. PHASE 1: MASTER PASSWORD
    print("\n[!] PHASE 1: MASTER PASSWORD CREATION")
    print("👉 Passwords will be hidden. Press [L-CTRL] to peek.")
    ph = PasswordHasher(memory_cost=MEM_COST, time_cost=TIME_COST, parallelism=PARALLELISM)
    
    while True:
        # Changed to maskpass.advpass for security
        mp = maskpass.advpass(prompt="🔑 CREATE MASTER PASSWORD (min 6): ", mask="*")
        confirm = maskpass.advpass(prompt="🔑 CONFIRM MASTER PASSWORD: ", mask="*")
        
        if mp == confirm:
            if len(mp) < 6: # Updated minimum requirement to 6 characters
                print("❌ ERROR: Password too short! Safety requires 6+ characters.")
                continue
            break
        print("❌ ERROR: Passwords do not match!")

    print("\n[⏳] Hashing password... (Using 200MB RAM)")
    mp_hash = ph.hash(mp)

    # 2. PHASE 2: MFA SETUP
    print("\n[!] PHASE 2: MULTI-FACTOR AUTHENTICATION (MFA)")
    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    uri = totp.provisioning_uri(name="v1.0.2", issuer_name="Aegis-1T")
    
    qr_filename = "mfa_setup_qr.png"
    qrcode.make(uri).save(qr_filename)

    print(f"\n[🎬] QR CODE GENERATED: {qr_filename}")
    
    try:
        if os.name == 'nt': os.startfile(qr_filename)
        else: os.system(f'open {qr_filename}')
    except:
        print("⚠️  Could not auto-open image. Please open 'mfa_setup_qr.png' manually.")

    print("\n" + "-"*40)
    print("📲 1. Open Google Authenticator / Authy")
    print("📲 2. Scan the QR code")
    print("📲 3. CLOSE THE IMAGE WINDOW on your computer")
    print("-"*40)
    
    input("\n👉 Once scanned and CLOSED, press ENTER to shred the QR code...")

    # --- SECURE SHREDDING OF QR CODE ---
    if os.path.exists(qr_filename):
        try:
            file_size = os.path.getsize(qr_filename)
            with open(qr_filename, "wb") as f:
                f.write(os.urandom(file_size)) 
                f.flush()
                os.fsync(f.fileno())
            os.remove(qr_filename)
            print("[🗑️] SECURITY: QR code securely wiped and deleted.")
        except Exception as e:
            print(f"⚠️  Warning: Delete '{qr_filename}' manually! Error: {e}")

    # 3. PHASE 3: VAULT SEALING
    print("\n[🔒] PHASE 3: SEALING THE VAULT...")
    
    # Payloads are combined and encrypted into the vault
    secret_payload = f"MASTER_HASH={mp_hash}\nMFA_SECRET={mfa_secret}"
    salt = get_random_bytes(16)
    
    vault_key = hash_secret_raw(
        secret=mp.encode(),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEM_COST,
        parallelism=PARALLELISM,
        hash_len=32,
        type=Type.ID
    )

    cipher = AES.new(vault_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(secret_payload.encode())

    vault_data = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    with open(".env.vault", "w") as f:
        json.dump(vault_data, f)

    print("\n" + "="*55)
    print("✅ SYSTEM INITIALIZED SUCCESSFULLY!")
    print("📍 VAULT CREATED: .env.vault")
    print("⚠️  This setup script will now self-destruct for security.")
    print("="*55 + "\n")
    
    # 4. SELF DESTRUCT LOGIC
    if os.name == 'nt':
        cmd = f'start /b "" cmd /c timeout /t 1 > nul & del "{sys.argv[0]}"'
        os.system(cmd)
    else:
        os.system(f'rm "{sys.argv[0]}" &')

if __name__ == "__main__":
    setup_aegis_vault()
