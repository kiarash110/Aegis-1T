import os
import sys
import shutil
import time

def run_diagnostic():
    print("🔍 [1/2] CHECKING LIBRARIES...")
    # List of modules we need
    modules = ['pyotp', 'qrcode', 'Crypto', 'argon2', 'maskpass']
    for mod in modules:
        try:
            __import__(mod)
            print(f"  ✅ {mod} is detected.")
        except ImportError:
            print(f"  ❌ {mod} is MISSING. Run: pip install {mod}")

    print("\n🔍 [2/2] CHECKING STORAGE...")
    _, _, free = shutil.disk_usage(".")
    print(f"  📂 Free Space: {free / (1024**3):.2f} GB")

if __name__ == "__main__":
    run_diagnostic()
