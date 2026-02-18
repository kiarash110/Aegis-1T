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

def delete_qr_after_delay(file_path, delay=120):
    """Wait for 'delay' seconds and then delete the file."""
    time.sleep(delay)
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"\n[🗑️] SECURITY: QR code image '{file_path}' has been securely deleted.")

def setup_aegis_vault():
    print("\n" + "="*50)
    print("🛡️  AEGIS-1T: SYSTEM INITIALIZATION")
    print("="*50)
    
    # --- PHASE 1: THE CRITICAL WARNING ---
    print("\n[!] PHASE 1: MASTER PASSWORD CREATION")
    print("⚠️  CRITICAL: If you lose this password, your")
    print("   vaulted data is PERMANENTLY UNRECOVERABLE.")
    print("   Choose a password you will NOT forget.\n")

    ph = PasswordHasher()
    while True:
        mp = input("🔑 CREATE MASTER PASSWORD: ")
        confirm = input("🔑 CONFIRM MASTER PASSWORD: ")
        
        if mp == confirm:
            if len(mp) < 8:
                print("❌ ERROR: Password must be at least 8 characters.")
                continue
            break
        print("❌ ERROR: Passwords do not match! Try again.")

    mp_hash = ph.hash(mp)

    # --- PHASE 2: MFA SETUP & AUTO-DELETE QR ---
    print("\n[!] PHASE 2: MULTI-FACTOR AUTHENTICATION (MFA)")
    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)
    
    uri = totp.provisioning_uri(name="Aegis-User", issuer_name="Aegis-1T")
    
    # Save QR code to a local file
    qr_filename = "mfa_setup_qr.png"
    qr_img = qrcode.make(uri)
    qr_img.save(qr_filename)

    print(f"\n[🎬] QR CODE GENERATED: {qr_filename}")
    print("⚠️  WARNING: You have 2 MINUTES to scan this.")
    print("    The image will be deleted automatically for your security.")
    
    # Start the self-destruct timer in the background
    threading.Thread(target=delete_qr_after_delay, args=(qr_filename,), daemon=True).start()
    
    # Open the image for the user
    os.startfile(qr_filename) if os.name == 'nt' else os.system(f'open {qr_filename}')

    # --- PHASE 3: SEALING THE SECRETS ---
    print("\n[🔒] PHASE 3: SEALING THE VAULT...")
    
    secret_payload = f"MASTER_HASH={mp_hash}\nMFA_SECRET={mfa_secret}"
    salt = get_random_bytes(16)
    
    vault_key = hash_secret_raw(
        secret=mp.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
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

    print("\n" + "="*50)
    print("✅ SETUP SUCCESSFUL!")
    print("📍 VAULT CREATED: .env.vault")
    print("⏱️  THE QR CODE WILL DELETE IN 2 MINUTES. FINISH SCANNING NOW.")
    print("="*50 + "\n")
    
    # Keep the script alive for a moment so the user reads the success message
    time.sleep(5)

if __name__ == "__main__":
    setup_aegis_vault()
