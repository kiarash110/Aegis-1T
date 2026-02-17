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
        f_out.flush()
        os.fsync(f_out.fileno())
    print(f"✅ Success! Created: {output_file}")

def decrypt_file(file_path, password):
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found.")
        return
    if not verify_user(): return
    
    with open(file_path, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        file_size = os.path.getsize(file_path)
        encrypted_data_size = file_size - SALT_SIZE - 16 - 16
        
        key = get_derived_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        output_file = file_path.replace(".aegis", "_decrypted.txt")
        
        with open(output_file, 'wb') as f_out:
            for _ in range(0, encrypted_data_size, BUFFER_SIZE):
                chunk = f_in.read(min(BUFFER_SIZE, encrypted_data_size))
                f_out.write(cipher.decrypt(chunk))
            tag = f_in.read(16)
            try:
                cipher.verify(tag)
                f_out.flush()
                os.fsync(f_out.fileno())
                print(f"🔓 Decrypted: {output_file}")
            except ValueError:
                print("❌ ERROR: Wrong password or corrupted file!")
                f_out.close()
                os.remove(output_file)

if __name__ == "__main__":
    print("\n--- 🛡️ Aegis-1T Vault Engine ---")
    action = input("Type 'E' to Encrypt or 'D' to Decrypt: ").upper()
    target = input("File path: ")
    secret_pass = input("Enter Vault Password: ")
    if action == 'E':
        encrypt_file(target, secret_pass)
    elif action == 'D':
        decrypt_file(target, secret_pass)
