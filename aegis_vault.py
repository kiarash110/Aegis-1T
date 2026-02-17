# =================================================================
# 🛡️ AEGIS-1T: HIGH-PERFORMANCE CRYPTOGRAPHIC ENGINE
# =================================================================
# DESCRIPTION: A terabyte-scale encryption tool using AES-256-GCM.
# SECURITY: Uses Argon2id for password hashing and TOTP for MFA.
# AUTHOR: [Your Name/GitHub Username]
# =================================================================

import os
import time
import pyotp
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# 🔑 STEP 1: LOAD SECRETS
# This reads the .env file where your MFA seed is hidden.
load_dotenv()

# --- ⚙️ ENGINE CONFIGURATION ---
# BUFFER_SIZE: 1MB. We process files in small bites so we don't crash the RAM.
# Even a 1TB file only uses 100MB of RAM because of this "Streaming" logic.
BUFFER_SIZE = 1024 * 1024  
SALT_SIZE = 16 # Random data added to the password to prevent "Rainbow Table" attacks.

def get_mfa_secret():
    """Fetches the 2FA secret from the .env vault."""
    secret = os.getenv("MFA_SECRET")
    if not secret:
        print("❌ Error: MFA not set up. Run setup_mfa.py first!")
        return None
    return secret

def verify_user():
    """
    🛡️ MULTI-FACTOR AUTHENTICATION CHECK
    Uses the pyotp library to sync with your phone's clock and 
    verify the 6-digit code.
    """
    secret = get_mfa_secret()
    if not secret: return False
    
    totp = pyotp.TOTP(secret)
    print(f"\n[!] MFA Required for Vault Access")
    user_code = input("🛡️ Enter 6-digit code from your phone: ")
    
    # Check if the code entered matches the one on the phone screen
    if totp.verify(user_code):
        print("✅ Access Granted!")
        return True
    else:
        print("❌ Invalid Code. Access Denied.")
        return False

def get_derived_key(password, salt):
    """
    🧠 THE 'BRAIN' - ARGON2id KEY DERIVATION
    This turns your simple text password into a 256-bit cryptographic key.
    It is designed to be slow and memory-heavy so hackers can't use 
    supercomputers to guess your password (brute-force).
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,      # How many times to scramble the data
        memory_cost=65536, # Use exactly 64MB of RAM to make it 'Memory-Hard'
        parallelism=4,    # Use 4 CPU cores at once
        hash_len=32,      # Output a 256-bit key for AES
        type=Type.ID      # Argon2id: The industry-standard variant
    )

def encrypt_file(file_path, password):
    """
    🔒 ENCRYPTION ENGINE
    Uses AES-GCM (Galois/Counter Mode) which provides both 
    Secrecy AND Integrity (it knows if the file was tampered with).
    """
    # Clean up the file path in case the user dragged-and-dropped it
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path):
        print(f"❌ Error: File not found: {file_path}")
        return

    # Don't try to encrypt air
    if os.path.getsize(file_path) == 0:
        print("⚠️ Warning: Source file is empty.")
        return

    # Check MFA before doing anything
    if not verify_user(): return
    
    print(f"🔒 Encrypting using Argon2id...")
    # Generate random 'Salt' for the password and 'Nonce' for the AES cipher
    salt = get_random_bytes(SALT_SIZE)
    key = get_derived_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM) # Initialize the AES-256-GCM engine
    
    output_file = file_path + ".aegis"
    
    # Write the encrypted file piece by piece
    with open(file_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)          # Store Salt at the start so we can decrypt later
        f_out.write(cipher.nonce)  # Store Nonce (the unique 'number once')
        
        while True:
            chunk = f_in.read(BUFFER_SIZE) # Read 1MB
            if not chunk: break
            f_out.write(cipher.encrypt(chunk)) # Encrypt and save 1MB
            
        # The 'Digest' is the digital signature. If one bit changes, decryption fails.
        f_out.write(cipher.digest())
        f_out.flush()
        os.fsync(f_out.fileno()) # Forces the OS to write to physical disk immediately

    print(f"✅ Success! Created: {output_file}")
    
    # --- 🧹 SECURE SHREDDER SECTION ---
    # This prevents forensic recovery of the original unencrypted file.
    print("\n" + "!" * 40)
    confirm_1 = input(f"🛡️  SHRED ORIGINAL? Delete '{os.path.basename(file_path)}'? (y/n): ").lower()
    
    if confirm_1 == 'y':
        print("⚠️  WARNING: This is permanent!")
        confirm_2 = input(f"    ARE YOU ABSOLUTELY SURE? (type 'yes'): ").lower()
        
        if confirm_2 == 'yes':
            try:
                # ZERO-FILL: Fill the file with zeros before deleting.
                # This makes it much harder for 'undelete' software to find the data.
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
    """
    🔓 DECRYPTION ENGINE
    Reverses the process. Reads the Salt and Nonce, rebuilds the key, 
    and verifies the file hasn't been corrupted.
    """
    file_path = file_path.strip('"').strip("'")
    if not os.path.exists(file_path): return
    if not verify_user(): return
    
    with open(file_path, 'rb') as f_in:
        # Read the metadata we saved during encryption
        salt = f_in.read(SALT_SIZE)
        nonce = f_in.read(16)
        
        file_size = os.path.getsize(file_path)
        # We subtract the salt, nonce, and the 16-byte signature (tag) 
        # to find the real data size.
        encrypted_data_size = file_size - SALT_SIZE - 16 - 16
        
        # Re-calculate the exact same key using the same password and salt
        key = get_derived_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        output_file = file_path.replace(".aegis", "")
        
        # Prevent overwriting existing files by adding a (1), (2), etc.
        counter = 1
        original_name = output_file
        while os.path.exists(output_file):
            name, ext = os.path.splitext(original_name)
            output_file = f"{name}({counter}){ext}"
            counter += 1

        with open(output_file, 'wb') as f_out:
            # Stream the data back out to disk
            for _ in range(0, encrypted_data_size, BUFFER_SIZE):
                chunk = f_in.read(min(BUFFER_SIZE, encrypted_data_size))
                f_out.write(cipher.decrypt(chunk))
            
            # THE MOMENT OF TRUTH: Verify the signature
            tag = f_in.read(16)
            try:
                cipher.verify(tag)
                print(f"🔓 Success! Restored: {os.path.basename(output_file)}")
            except ValueError:
                # If the password is wrong OR a hacker changed 1 byte of the file.
                print("❌ ERROR: Verification failed. Wrong password or tampered file!")
                f_out.close()
                os.remove(output_file) # Delete the corrupted file

# --- 🚀 USER INTERFACE ---
if __name__ == "__main__":
    print("\n--- 🛡️ Aegis-1T Vault (Argon2id + AES-GCM) ---")
    action = input("Type 'E' to Encrypt or 'D' to Decrypt: ").upper()
    target = input("File path: ")
    secret_pass = input("Enter Vault Password: ")
    
    if action == 'E':
        encrypt_file(target, secret_pass)
    elif action == 'D':
        decrypt_file(target, secret_pass)
