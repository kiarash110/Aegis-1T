import os
import pyotp
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# --- CONFIGURATION ---
BUFFER_SIZE = 1024 * 1024  # 1MB chunks for performance
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
    # Clean the path
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found at {file_path}")
        return

    # Heartbeat delay to ensure Windows has finished writing the file
    time.sleep(0.5)
    
    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        print("⚠️ Warning: Source file is 0 bytes. Please save content first.")
        return

    if not verify_user(): return
    
    print(f"🔒 Encrypting...")
    salt = get_random_bytes(SALT_SIZE)
    key = get_derived_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    output_file = file_path + ".aegis"
    
    # We read the whole file for smaller files, or stream for larger ones
    # This combination prevents the 'empty file' issue on Windows
    with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.nonce)
        
        while True:
            chunk = f_in.read(BUFFER_SIZE)
            if not chunk:
                break
            f_out.write(cipher.encrypt(chunk))
            
        f_out.write(cipher.digest())
        f_out.flush()
        os.fsync(f_out.fileno())

    print(f"✅ Success! Created: {output_file}")
    
    # --- THE SHREDDER ---
    print("\n" + "!" * 40)
    confirm = input(f"🛡️  SHRED ORIGINAL? Delete '{os.path.basename(file_path)}'? (y/n): ").lower()
    if confirm == 'y':
        try:
            os.remove(file_path)
            print(f"🗑️  Original file shredded.")
        except Exception as e:
            print(f"⚠️  Could not shred file: {e}")
    else:
        print("📁 Original file kept.")

def decrypt_file(file_path, password):
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path):
        print("❌ Error: File not found.")
        return
    if not verify_user(): return
    
    with open(file_path, 'rb') as f_in:
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        
        # Calculate size of ciphertext
        file_size = os.path.getsize(file_path)
        encrypted_data_size = file_size - SALT_SIZE - 16 - 16
        
        key = get_derived_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Smart naming: removes .aegis and restores original extension
        output_file = file_path.replace(".aegis", "_decrypted")
        if not any(ext in output_file for ext in ['.txt', '.jpg', '.png', '.pdf']):
            output_file += ".txt" # Default to txt if unknown

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
