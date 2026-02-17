import os
import time
import pyotp
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# Load environment variables (for MFA secret)
load_dotenv()

# --- CONFIGURATION ---
BUFFER_SIZE = 1024 * 1024  # 1MB chunks
SALT_SIZE = 16

def get_mfa_secret():
    secret = os.getenv("MFA_SECRET")
    if not secret:
        print("❌ Error: MFA not set up. Run setup_mfa.py first!")
        return None
    return secret

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
    """
    Implements Argon2id Key Derivation.
    This is memory-hard and time-hard to prevent GPU cracking.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,      # Iterations
        memory_cost=65536, # 64MB RAM usage
        parallelism=4,    # Threads
        hash_len=32,      # 256-bit key
        type=Type.ID      # Argon2id variant
    )

def encrypt_file(file_path, password):
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        return

    if os.path.getsize(file_path) == 0:
        print("⚠️ Warning: Source file is empty.")
        return

    if not verify_user(): return
    
    print(f"🔒 Encrypting using Argon2id...")
    salt = get_random_bytes(SALT_SIZE)
    key = get_derived_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    output_file = file_path + ".aegis"
    
    with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.nonce)
        
        while True:
            chunk = f_in.read(BUFFER_SIZE)
            if not chunk: break
            f_out.write(cipher.encrypt(chunk))
            
        f_out.write(cipher.digest())
        f_out.flush()
        os.fsync(f_out.fileno())

    print(f"✅ Success! Created: {output_file}")
    
    # --- MANUAL SECURE SHREDDER ---
    print("\n" + "!" * 40)
    confirm_1 = input(f"🛡️  SHRED ORIGINAL? Delete '{os.path.basename(file_path)}'? (y/n): ").lower()
    
    if confirm_1 == 'y':
        print("⚠️  WARNING: This is permanent!")
        confirm_2 = input(f"   ARE YOU ABSOLUTELY SURE? (type 'yes'): ").lower()
        
        if confirm_2 == 'yes':
            try:
                # Overwrite with zeros before deleting (Zero-Fill)
                size = os.path.getsize(file_path)
                with open(file_path, "ba+", buffering=0) as f:
                    f.write(b"\x00" * size)
                os.remove(file_path)
                print(f"🗑️  Original file zero-filled and shredded.")
            except Exception as e:
                print(f"⚠️  Shred failed: {e}")
    else:
        print("📁 Original file kept.")

def decrypt_file(file_path, password):
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path): return
    if not verify_user(): return
    
    with open(file_path, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        
        file_size = os.path.getsize(file_path)
        # Auth tag is the last 16 bytes
        encrypted_data_size = file_size - SALT_SIZE - 16 - 16
        
        key = get_derived_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        output_file = file_path.replace(".aegis", "")
        # Handle file conflicts
        counter = 1
        original_name = output_file
        while os.path.exists(output_file):
            name, ext = os.path.splitext(original_name)
            output_file = f"{name}({counter}){ext}"
            counter += 1

        with open(output_file, 'wb') as f_out:
            for _ in range(0, encrypted_data_size, BUFFER_SIZE):
                chunk = f_in.read(min(BUFFER_SIZE, encrypted_data_size))
                f_out.write(cipher.decrypt(chunk))
            
            tag = f_in.read(16)
            try:
                cipher.verify(tag)
                print(f"🔓 Success! Restored: {os.path.basename(output_file)}")
            except ValueError:
                print("❌ ERROR: Verification failed. Wrong password or tampered file!")
                f_out.close()
                os.remove(output_file)

if __name__ == "__main__":
    print("\n--- 🛡️ Aegis-1T Vault (Argon2id + AES-GCM) ---")
    action = input("Type 'E' to Encrypt or 'D' to Decrypt: ").upper()
    target = input("File path: ")
    secret_pass = input("Enter Vault Password: ")
    
    if action == 'E':
        encrypt_file(target, secret_pass)
    elif action == 'D':
        decrypt_file(target, secret_pass)
