import pyotp
import qrcode
import os
import json
import base64
import time
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

# --- HIGH-SECURITY CONFIGURATION ---
MEM_COST = 204800  # 200MB 
TIME_COST = 4      # Number of passes
PARALLELISM = 4    # CPU Threads
# -----------------------------------

def delete_qr_after_delay(file_path, delay=120):
    """Securely deletes the QR image after 2 minutes."""
    time.sleep(delay)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            print(f"\n[🗑️] SECURITY: QR code image '{file_path}' deleted.")
        except:
            pass

def setup_aegis_vault():
    print("\n" + "="*55)
    print("🛡️  AEGIS-1T: SYSTEM INITIALIZATION (200MB RAM MODE)")
    print("="*55)
    
    # 1. WARNING & PASSWORD
    print("\n[!] PHASE 1: MASTER PASSWORD CREATION")
    print("⚠️  CRITICAL: If you lose this password, your")
    print("   vaulted data is PERMANENTLY UNRECOVERABLE.\n")

    ph = PasswordHasher(memory_cost=MEM_COST, time_cost=TIME_COST, parallelism=PARALLELISM)
    
    while True:
        mp = input("🔑 CREATE MASTER PASSWORD: ")
        confirm = input("🔑 CONFIRM MASTER PASSWORD: ")
        
        if mp == confirm:
            if len(mp) < 12:
                print("❌ ERROR: For high-security, use at least 12 characters.")
                continue
            break
        print("❌ ERROR: Passwords do not match!")

    print("\n[⏳] Hashing password... (Using 200MB RAM)")
    mp_hash = ph.hash(mp)

    # 2. MFA SETUP
    print("\n[!] PHASE 2: MULTI-FACTOR AUTHENTICATION (MFA)")
    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    uri = totp.provisioning_uri(name="Aegis-User", issuer_name="Aegis-1T")
    
    qr_filename = "mfa_setup_qr.png"
    qrcode.make(uri).save(qr_filename)

    print(f"\n[🎬] QR CODE GENERATED: {qr_filename}")
    print("⚠️  WARNING: You have 2 MINUTES to scan this.")
    
    threading.Thread(target=delete_qr_after_delay, args=(qr_filename,), daemon=True).start()
    
    # Open image (Windows/Mac/Linux)
    if os.name == 'nt': os.startfile(qr_filename)
    else: os.system(f'open {qr_filename}')

    # 3. VAULT SEALING
    print("\n[🔒] PHASE 3: SEALING THE VAULT...")
    
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
    print("✅ SETUP SUCCESSFUL!")
    print(f"📍 VAULT CREATED: .env.vault ({MEM_COST//1024}MB Hardness)")
    print("⏱️  FINISH SCANNING THE QR CODE BEFORE IT DELETES.")
    print("="*55 + "\n")
    time.sleep(5)

if __name__ == "__main__":
    setup_aegis_vault()
