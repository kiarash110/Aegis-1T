import os, pyotp, json, base64, maskpass, time, psutil, shutil
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# --- CORE CRYPTO CONFIGURATION ---
MEM_COST, TIME_COST, PARALLELISM, SALT_SIZE = 204800, 4, 4, 16

def system_audit():
    print("\n" + "═"*45)
    print("🛡️  AEGIS-1T: SYSTEM PRE-FLIGHT CHECK")
    print("═"*45)
    print("\n📦 Checking Dependencies...")
    required = ['pyotp', 'maskpass', 'cryptodome', 'argon2', 'psutil']
    for lib in required:
        try:
            if lib == 'cryptodome': __import__('Crypto')
            else: __import__(lib)
            print(f"  ✅ {lib} is active.")
        except ImportError:
            print(f"  ❌ {lib} is MISSING.")
    available_gb = psutil.virtual_memory().available / (1024**3)
    print(f"\n🧠 RAM: {available_gb:.2f} GB Free")
    input("\nPress Enter to return...")

def select_buffer_mode(task_name):
    print(f"\n🚀 SELECT SPEED FOR {task_name.upper()}:")
    print(" [1] Standard (16MB) | [2] Extreme (512MB) | [3] NITRO (1.5GB)")
    choice = input(f"👉 Select Mode (1/2/3): ")
    if choice == '3': return 1536 * 1024 * 1024
    if choice == '2': return 512 * 1024 * 1024
    return 16 * 1024 * 1024

def display_progress(current, total, start_time):
    elapsed = time.time() - start_time
    percent = (current / total) * 100
    speed = (current / (1024 * 1024)) / elapsed if elapsed > 0 else 0
    remaining = (total - current) / (current / elapsed) if current > 0 else 0
    bar = '█' * int(30 * current // total) + '-' * (30 - int(30 * current // total))
    print(f"\r|{bar}| {percent:.1f}% - {speed:.2f} MB/s - ETA: {int(remaining)}s ", end='')

def secure_shred(file_path):
    """FIX #1: Checks confirmation BEFORE asking for buffer speed"""
    if not file_path.exists(): return
    
    print(f"\n\n🧹 SHREDDER INITIALIZED")
    print(f"⚠️  CRITICAL: Shredding will permanently destroy: {file_path.name}")
    
    # Triple Confirmation FIRST
    if input("👉 Confirm Shredding? (y/n): ").lower() != 'y': return print("🚫 Shredding Canceled.")
    if input("👉 ARE YOU SURE? (y/n): ").lower() != 'y': return print("🚫 Shredding Canceled.")
    if input("👉 Final warning: Type 'DELETE' to proceed: ") != 'DELETE': return print("🚫 Shredding Canceled.")

    # Speed Selection SECOND
    shred_buffer = select_buffer_mode("Shredding")

    if file_path.is_dir():
        shutil.rmtree(file_path)
        print(f"✨ FOLDER SHREDDED SUCCESSFULLY.")
    else:
        file_size = file_path.stat().st_size
        start_time, processed = time.time(), 0
        print(f"\n🧹 Wiping original file...")
        try:
            with open(file_path, "wb") as f:
                while processed < file_size:
                    chunk = min(shred_buffer, file_size - processed)
                    f.write(os.urandom(chunk))
                    f.flush()
                    os.fsync(f.fileno()) 
                    processed += chunk
                    display_progress(processed, file_size, start_time)
            os.remove(file_path)
            print(f"\n✨ FILE SHREDDED SUCCESSFULLY.")
        except Exception as e:
            print(f"\n❌ SHREDDING FAILED: {e}")

def unlock_vault(master_password):
    if not os.path.exists(".env.vault"): return None
    try:
        with open(".env.vault", "r") as f: vault = json.load(f)
        salt = base64.b64decode(vault['salt'])
        vault_key = hash_secret_raw(master_password.encode(), salt=salt, time_cost=TIME_COST, 
                                     memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
        cipher = AES.new(vault_key, AES.MODE_GCM, nonce=base64.b64decode(vault['nonce']))
        decrypted = cipher.decrypt_and_verify(base64.b64decode(vault['ciphertext']), base64.b64decode(vault['tag']))
        return {k: v for line in decrypted.decode().split('\n') if '=' in line for k, v in [line.split('=', 1)]}
    except: return None

if __name__ == "__main__":
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*60)
        print("🛡️  AEGIS-1T | VERSION 1.0.3 | PERFORMANCE SUITE")
        print("="*60)
        
        action = input("\n[E]ncrypt, [D]ecrypt, [S]ystem Audit, [Q]uit: ").upper()
        if action == 'Q': break
        if action == 'S': system_audit(); continue 

        path_raw = input("\n👉 Drag & Drop Path: ").strip().strip('"').strip("'")
        target = Path(path_raw)
        if not target.exists():
            print("❌ Path not found."); time.sleep(2); continue

        is_folder = target.is_dir()
        temp_zip = None

        if action == 'E':
            if target.suffix == '.aegis':
                print("\n🛑 ERROR: Already encrypted."); time.sleep(3); continue
            
            if is_folder:
                print(f"📦 Bundling folder '{target.name}'...")
                temp_zip = target.with_name(target.name + "_bundle.zip")
                # Updated zip logic to avoid path recursion
                shutil.make_archive(str(temp_zip).replace('.zip', ''), 'zip', target)
                target = temp_zip

        # Passwords & MFA
        master_pass = maskpass.advpass(prompt="🔑 Master Password: ", mask="*")
        vault = unlock_vault(master_pass)
        if not vault:
            print("❌ Denied."); time.sleep(2); continue

        file_pass = maskpass.advpass(prompt="🛡️  File Password: ", mask="*")
        buffer_size = select_buffer_mode("Processing")
        
        if not pyotp.TOTP(vault.get("MFA_SECRET")).verify(input("\n🛡️  Enter MFA code: ")):
            print("❌ MFA Invalid."); time.sleep(2); continue

        start_time, processed = time.time(), 0
        file_size = target.stat().st_size
        
        try:
            if action == 'E':
                salt = get_random_bytes(SALT_SIZE)
                key = hash_secret_raw(file_pass.encode(), salt=salt, time_cost=TIME_COST, memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
                cipher = AES.new(key, AES.MODE_GCM)
                output_path = target.with_suffix(target.suffix + ".aegis")
                
                with open(target, 'rb') as f_in, open(output_path, 'wb') as f_out:
                    f_out.write(salt)
                    f_out.write(cipher.nonce)
                    while (chunk := f_in.read(buffer_size)):
                        f_out.write(cipher.encrypt(chunk))
                        processed += len(chunk)
                        display_progress(processed, file_size, start_time)
                    f_out.write(cipher.digest())
                
                print(f"\n\n✅ ENCRYPTION COMPLETE")
                if is_folder: os.remove(target) # Clean up temp zip
                secure_shred(Path(path_raw)) # Shred original source

            elif action == 'D':
                # FIX #2: Refined decryption pointer logic
                with open(target, 'rb') as f_in:
                    salt = f_in.read(SALT_SIZE)
                    nonce = f_in.read(16)
                    data_size = file_size - SALT_SIZE - 16 - 16 # Salt + Nonce + Tag
                    
                    key = hash_secret_raw(file_pass.encode(), salt=salt, time_cost=TIME_COST, memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    
                    # Clean the suffix for output
                    output_name = target.name.replace(".aegis", "")
                    output_path = target.parent / output_name
                    
                    with open(output_path, 'wb') as f_out:
                        while processed < data_size:
                            chunk = f_in.read(min(buffer_size, data_size - processed))
                            f_out.write(cipher.decrypt(chunk))
                            processed += len(chunk)
                            display_progress(processed, data_size, start_time)
                        
                        tag = f_in.read(16)
                        try:
                            cipher.verify(tag)
                            print(f"\n\n🔓 DECRYPTION SUCCESSFUL")
                            
                            # Auto-Unbundle Check
                            if "_bundle.zip" in output_path.name:
                                print(f"📦 Unbundling folder...")
                                final_dir = output_path.parent / output_path.name.replace("_bundle.zip", "")
                                shutil.unpack_archive(str(output_path), str(final_dir), 'zip')
                                os.remove(output_path)
                        except Exception as ve:
                            f_out.close()
                            if output_path.exists(): os.remove(output_path)
                            print(f"\n❌ INTEGRITY FAILURE: Wrong password or corrupt data. {ve}")

        except Exception as e:
            print(f"\n❌ CRITICAL ERROR: {e}")
        
        if input("\n🔄 Task complete. Process another? (y/n): ").lower() != 'y':
            break
