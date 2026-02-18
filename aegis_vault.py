import os
import pyotp
import maskpass  # Anti-Keylogger Protection
from pathlib import Path # Pro Path Handling (No more quote issues)
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# 🔑 STEP 1: LOAD SECRETS
load_dotenv()

BUFFER_SIZE = 1024 * 1024  # 1MB Chunks for large files
SALT_SIZE = 16 

def clean_path_input(prompt):
    """
    🛠️ PRO PATH SANITIZER
    Handles Drag & Drop or 'Copy as Path' automatically.
    Removes "" and '' and extra spaces.
    """
    raw_path = input(prompt).strip().strip('"').strip("'")
    return Path(raw_path)

def get_mfa_secret():
    secret = os.getenv("MFA_SECRET")
    if not secret:
        print("❌ Error: MFA_SECRET not found in .env!")
        return None
    return secret

def verify_user():
    """ 🛡️ MFA CHECK """
    secret = get_mfa_secret()
    if not secret: return False
    
    totp = pyotp.TOTP(secret)
    print(f"\n[!] MFA Required for Access")
    user_code = input("🛡️ Enter 6-digit code from phone: ")
    
    if totp.verify(user_code):
        print("✅ Access Granted.")
        return True
    else:
        print("❌ Access Denied.")
        return False

def get_derived_key(password, salt):
    """ 🧠 ARGON2id KEY DERIVATION """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536, # Uses 64MB of RAM
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

def encrypt_file(file_path_obj, password):
    """ 🔒 AES-256-GCM ENCRYPTION """
    if not file_path_obj.exists():
        print(f"❌ Error: Path '{file_path_obj}' not found.")
        return

    if not verify_user(): return
    
    print(f"🔒 Encrypting: {file_path_obj.name}...")
    salt = get_random_bytes(SALT_SIZE)
    key = get_derived_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    
    output_file = file_path_obj.with_suffix(file_path_obj.suffix + ".aegis")
    
    with open(file_path_obj, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.nonce)
        
        while True:
            chunk = f_in.read(BUFFER_SIZE)
            if not chunk: break
            f_out.write(cipher.encrypt(chunk))
            
        f_out.write(cipher.digest())

    print(f"✅ Success! Created: {output_file.name}")
    
    # 🧹 SECURE SHREDDER
    confirm = input(f"🛡️ SHRED ORIGINAL '{file_path_obj.name}'? (y/n): ").lower()
    if confirm == 'y':
        size = file_path_obj.stat().st_size
        with open(file_path_obj, "ba+", buffering=0) as f:
            f.write(b"\x00" * size)
        os.remove(file_path_obj)
        print(f"🗑️ Shredded successfully.")

def decrypt_file(file_path_obj, password):
    """ 🔓 DECRYPTION & INTEGRITY CHECK """
    if not file_path_obj.exists(): return
    if not verify_user(): return
    
    with open(file_path_obj, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        
        file_size = file_path_obj.stat().st_size
        # Metadata check: salt(16) + nonce(16) + tag(16) = 48 bytes
        encrypted_data_size = file_size - SALT_SIZE - 16 - 16
        
        key = get_derived_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Strip .aegis to get original name
        output_file = Path(str(file_path_obj).replace(".aegis", ""))
        
        # Overwrite protection
        base_name = output_file
        counter = 1
        while output_file.exists():
            output_file = base_name.with_name(f"{base_name.stem}({counter}){base_name.suffix}")
            counter += 1

        with open(output_file, 'wb') as f_out:
            for _ in range(0, encrypted_data_size, BUFFER_SIZE):
                chunk = f_in.read(min(BUFFER_SIZE, encrypted_data_size))
                f_out.write(cipher.decrypt(chunk))
            
            tag = f_in.read(16)
            try:
                cipher.verify(tag)
                print(f"🔓 Success! Restored to: {output_file.name}")
            except ValueError:
                print("❌ ERROR: Integrity failed (Wrong password or file tampered).")
                f_out.close()
                os.remove(output_file)

# --- 🚀 INTERFACE ---
if __name__ == "__main__":
    print("\n" + "="*40)
    print("🛡️  AEGIS-1T CRYPTOGRAPHIC VAULT")
    print("="*40)
    
    action = input("Type 'E' to Encrypt or 'D' to Decrypt: ").upper()
    
    # Drag and Drop the file here
    target_path = clean_path_input("📍 Drag & Drop (or paste path): ")
    
    # Password entry (Hidden from keyloggers)
    secret_pass = maskpass.advpass(prompt="🔑 Enter Master Password: ", mask="*")
    
    if action == 'E':
        encrypt_file(target_path, secret_pass)
    elif action == 'D':
        decrypt_file(target_path, secret_pass)
