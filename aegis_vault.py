import os
import pyotp
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# --- CONFIGURATION ---
BUFFER_SIZE = 64 * 1024  # 64KB chunks for memory efficiency
SALT_SIZE = 16

def get_mfa_secret():
    if not os.path.exists(".env"):
        print("❌ Error: MFA not set up. Run setup_mfa.py first!")
        return None
    with open(".env", "r") as f:
        for line in f:
            if "MFA_SECRET=" in line:
                return line.strip().split("=")[1]
    return None

def verify_user():
    secret = get_mfa_secret()
    if not secret: return False
    totp = pyotp.TOTP(secret)
    print(f"\n[!] MFA Required for Vault Access")
    user_code = input("🛡️ Enter 6-digit code from your phone: ")
    if totp.verify(user_code):
        print("✅ Access Granted!")
        return True
    else:
        print("❌ Invalid Code. Access Denied.")
        return False

def get_derived_key(password, salt):
    return scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

def encrypt_file(file_path, password):
    # Strip quotes if the user accidentally included them
    file_path = file_path.strip('"').strip("'")
    
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found at {file_path}")
        return

    if not verify_user(): return
    
    salt = get_random_bytes(SALT_SIZE)
    key = get_derived_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    
    output_file = file_path + ".aegis"
    print(f"🔒 Encrypting...")
    
    with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.nonce)
        
        while True:
            chunk = f_in.read(BUFFER_SIZE)
            if len(chunk) == 0: break
            f_out.write(cipher.encrypt(chunk))
            
        f_out.write(cipher.digest())
        
        # --- THE FIX: FORCE DATA TO DISK ---
        f_out.flush()
        os.fsync(f_out.fileno())
    
    print(f"✅ Success! Created: {output_file}")
    print(f"📦 File size: {os.path.getsize(output_file)} bytes")

def decrypt_file(file_path, password):
    file_path = file
