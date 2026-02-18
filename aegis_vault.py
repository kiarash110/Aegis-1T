import os
import pyotp
import json
import base64
import maskpass
import time
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# --- CONFIGURATION ---
MEM_COST = 204800  
TIME_COST = 4      
PARALLELISM = 4    
BUFFER_SIZE = 5 * 1024 * 1024  # 🚀 5MB Buffer for speed
SALT_SIZE = 16

def clean_path_input(prompt):
    raw_path = input(prompt).strip().strip('"').strip("'")
    return Path(raw_path)

def display_progress(current, total, start_time):
    """🛠️ Custom Progress Bar with Speed & ETA"""
    elapsed = time.time() - start_time
    percent = (current / total) * 100
    # Calculate Speed (MB/s)
    speed = (current / (1024 * 1024)) / elapsed if elapsed > 0 else 0
    # Calculate ETA (seconds)
    remaining = (total - current) / (current / elapsed) if current > 0 else 0
    
    # Format the bar
    bar_length = 30
    filled = int(bar_length * current // total)
    bar = '█' * filled + '-' * (bar_length - filled)
    
    print(f"\r|{bar}| {percent:.1f}% - {speed:.2f} MB/s - ETA: {int(remaining)}s ", end='')

def unlock_vault(password):
    if not os.path.exists(".env.vault"):
        print("❌ Error: .env.vault missing.")
        return None
    try:
        with open(".env.vault", "r") as f:
            vault = json.load(f)
        salt = base64.b64decode(vault['salt'])
        vault_key = hash_secret_raw(
            secret=password.encode(), salt=salt,
            time_cost=TIME_COST, memory_cost=MEM_COST,
            parallelism=PARALLELISM, hash_len=32, type=Type.ID
        )
        cipher = AES.new(vault_key, AES.MODE_GCM, nonce=base64.b64decode(vault['nonce']))
        decrypted_data = cipher.decrypt_and_verify(
            base64.b64decode(vault['ciphertext']), base64.b64decode(vault['tag'])
        )
        secrets = {}
        for line in decrypted_data.decode().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                secrets[k] = v
        return secrets
    except:
        return None

def get_file_key(password, salt):
    return hash_secret_raw(
        secret=password.encode(), salt=salt,
        time_cost=TIME_COST, memory_cost=MEM_COST,
        parallelism=PARALLELISM, hash_len=32, type=Type.ID
    )

def encrypt_file(file_path, password, mfa_secret):
    totp = pyotp.TOTP(mfa_secret)
    user_code = input("\n🛡️ Enter MFA code: ")
    if not totp.verify(user_code): return print("❌ Access Denied")

    file_size = file_path.stat().st_size
    salt = get_random_bytes(SALT_SIZE)
    key = get_file_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    output_file = file_path.with_suffix(file_path.suffix + ".aegis")
    
    start_time = time.time()
    processed = 0
    
    with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.nonce)
        while True:
            chunk = f_in.read(BUFFER_SIZE)
            if not chunk: break
            f_out.write(cipher.encrypt(chunk))
            processed += len(chunk)
            display_progress(processed, file_size, start_time)

        f_out.write(cipher.digest())
    
    print(f"\n✅ Done! File locked as {output_file.name}")
    if input(f"\n🛡️ Shred original? (y/n): ").lower() == 'y':
        with open(file_path, "wb") as f: f.write(os.urandom(file_size))
        os.remove(file_path)
        print("🗑️ Shredded.")

def decrypt_file(file_path, password, mfa_secret):
    totp = pyotp.TOTP(mfa_secret)
    user_code = input("\n🛡️ Enter MFA code: ")
    if not totp.verify(user_code): return print("❌ Access Denied")

    with open(file_path, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        file_size = file_path.stat().st_size
        encrypted_data_size = file_size - SALT_SIZE - 16 - 16
        
        key = get_file_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        output_file = Path(str(file_path).replace(".aegis", ""))
        
        start_time = time.time()
        processed = 0
        
        with open(output_file, 'wb') as f_out:
            while processed < encrypted_data_size:
                to_read = min(BUFFER_SIZE, encrypted_data_size - processed)
                chunk = f_in.read(to_read)
                if not chunk: break
                f_out.write(cipher.decrypt(chunk))
                processed += len(chunk)
                display_progress(processed, encrypted_data_size, start_time)
            
            tag = f_in.read(16)
            try:
                cipher.verify(tag)
                print(f"\n🔓 Success! File restored.")
            except:
                print("\n❌ Integrity check failed!")
                f_out.close()
                os.remove(output_file)

if __name__ == "__main__":
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("🛡️ AEGIS-1T (5MB BUFFER MODE)")
        action = input("\n[E]ncrypt, [D]ecrypt, [Q]uit: ").upper()
        if action == 'Q': break
        if action not in ['E', 'D']: continue

        target = clean_path_input("📍 File Path: ")
        if not target.exists(): continue

        password = maskpass.advpass(prompt="🔑 Password: ", mask="*")
        vault = unlock_vault(password)
        
        if vault:
            mfa_secret = vault.get("MFA_SECRET")
            if action == 'E': encrypt_file(target, password, mfa_secret)
            else: decrypt_file(target, password, mfa_secret)
        
        if input("\n🔄 Again? (y/n): ").lower() != 'y': break
