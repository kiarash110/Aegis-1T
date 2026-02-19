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
    print(" [1] Standard (16MB Buffer)  - RAM Usage: ~100MB")
    print(" [2] Extreme  (512MB Buffer) - RAM Usage: ~1.2GB")
    print(" [3] NITRO    (1.5GB Buffer) - RAM Usage: ~3.5GB+")
    
    choice = input(f"👉 Select {task_name} Mode (1/2/3): ")
    if choice == '3':
        print("🔥 NITRO ENABLED: Ensure you have 16GB+ System RAM available.")
        return 1536 * 1024 * 1024
    if choice == '2':
        return 512 * 1024 * 1024
    return 16 * 1024 * 1024

def display_progress(current, total, start_time):
    elapsed = time.time() - start_time
    percent = (current / total) * 100
    speed = (current / (1024 * 1024)) / elapsed if elapsed > 0 else 0
    remaining = (total - current) / (current / elapsed) if current > 0 else 0
    bar = '█' * int(30 * current // total) + '-' * (30 - int(30 * current // total))
    print(f"\r|{bar}| {percent:.1f}% - {speed:.2f} MB/s - ETA: {int(remaining)}s ", end='')

def secure_shred(file_path):
    if not file_path.exists(): return
    print(f"\n\n🧹 SHREDDER INITIALIZED")
    
    # CONFIRMATION FIRST
    print(f"\n⚠️  CRITICAL: Shredding will permanently destroy: {file_path.name}")
    if input("👉 Confirm Shredding? (y/n): ").lower() != 'y': return print("🚫 Canceled.")
    if input("👉 ARE YOU SURE? (y/n): ").lower() != 'y': return print("🚫 Canceled.")
    if input("👉 Final warning: Type 'DELETE' to proceed: ") != 'DELETE': return print("🚫 Canceled.")

    # SPEED SECOND
    shred_buffer = select_buffer_mode("Shredding")

    if file_path.is_dir():
        shutil.rmtree(file_path)
        print(f"\n✨ SHRED COMPLETE: Folder deleted.")
    else:
        file_size = file_path.stat().st_size
        start_time, processed = time.time(), 0
        print(f"\n🧹 Wiping original file with random bytes...")
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
            total_time = time.time() - start_time
            print(f"\n✨ SHRED COMPLETE: {total_time:.2f}s | Avg: {(file_size/(1024*1024))/total_time:.2f} MB/s")
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
        print("🛡️  AEGIS-1T | VERSION 1.0.5 | PERFORMANCE SUITE")
        print("="*60)
        
        action = input("\n[E]ncrypt, [D]ecrypt, [S]ystem Audit, [Q]uit: ").upper()
        if action == 'Q': break
        if action == 'S': system_audit(); continue 

        target_input = input("\n👉 Drag & Drop Or Type/Paste The Path: ").strip().strip('"').strip("'")
        target = Path(target_input)
        if not target.exists():
            print("❌ File not found."); time.sleep(2); continue

        # 1. Password Step
        while True:
            print("\n" + "─"*55)
            print("🔒 SECURITY: Passwords show as '*'. Press [L-CTRL] to peek.")
            print("─" * 55)
            master_pass = maskpass.advpass(prompt="🔑 System Master Password: ", mask="*")
            if len(master_pass) >= 6: break
            print("⚠️  Master Password must be at least 6 characters.")

        vault = unlock_vault(master_pass)
        if not vault:
            print("❌ Access Denied."); time.sleep(2); continue

        # 2. MFA Step (Moved up before any file processing)
        if not pyotp.TOTP(vault.get("MFA_SECRET")).verify(input("\n🛡️  Enter MFA code: ")):
            print("❌ MFA Invalid."); time.sleep(2); continue

        # 3. File Password & Speed Selection
        file_pass = maskpass.advpass(prompt="🛡️  File-Specific Password: ", mask="*")
        buffer_size = select_buffer_mode("Processing")

        is_folder = target.is_dir()
        temp_zip = None

        try:
            if action == 'E':
                if target.suffix == '.aegis':
                    print("\n🛑 ERROR: Already encrypted."); time.sleep(4); continue
                
                # Bundle ONLY if MFA passed
                if is_folder:
                    print(f"📦 Bundling folder '{target.name}' for encryption...")
                    temp_zip = target.with_name(target.name + "_bundle.zip")
                    shutil.make_archive(str(temp_zip).replace('.zip', ''), 'zip', target)
                    target = temp_zip

                start_time, processed = time.time(), 0
                file_size = target.stat().st_size
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
                
                duration = time.time() - start_time
                print(f"\n\n✅ ENCRYPTION COMPLETE")
                print(f"📊 Time: {int(duration // 60)}m {int(duration % 60)}s | Speed: {(file_size/(1024*1024))/duration:.2f} MB/s")
                print(f"📦 Final Size: {output_path.stat().st_size / (1024**3):.4f} GB")
                
                if is_folder: os.remove(target)
                secure_shred(Path(target_input))

            elif action == 'D':
                start_time, processed = time.time(), 0
                file_size = target.stat().st_size
                with open(target, 'rb') as f_in:
                    salt = f_in.read(SALT_SIZE)
                    nonce = f_in.read(16)
                    data_size = file_size - SALT_SIZE - 16 - 16 
                    
                    key = hash_secret_raw(file_pass.encode(), salt=salt, time_cost=TIME_COST, memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    output_path = Path(str(target).replace(".aegis", ""))
                    
                    with open(output_path, 'wb') as f_out:
                        while processed < data_size:
                            chunk = f_in.read(min(buffer_size, data_size - processed))
                            f_out.write(cipher.decrypt(chunk))
                            processed += len(chunk)
                            display_progress(processed, data_size, start_time)
                        tag = f_in.read(16)
                    
                    try:
                        cipher.verify(tag)
                        duration = time.time() - start_time
                        print(f"\n\n🔓 DECRYPTION SUCCESSFUL")
                        print(f"📊 Time: {int(duration // 60)}m {int(duration % 60)}s | Speed: {(data_size/(1024*1024))/duration:.2f} MB/s")
                        
                        if "_bundle.zip" in output_path.name:
                            print(f"📦 Unbundling folder content...")
                            final_dir = output_path.parent / output_path.name.replace("_bundle.zip", "")
                            shutil.unpack_archive(str(output_path), str(final_dir), 'zip')
                            os.remove(output_path)
                    except:
                        if output_path.exists(): os.remove(output_path)
                        print("\n❌ INTEGRITY FAILURE: Wrong password or corrupt file.")
        except Exception as e:
            print(f"\n❌ CRITICAL ERROR: {e}")
        
        if input("\n🔄 Task complete. Process another file? (y/n): ").lower() != 'y':
            break
