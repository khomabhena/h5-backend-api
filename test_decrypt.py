"""
Test script to decrypt a callback payload
Usage: python test_decrypt.py
"""
import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'h5_backend_api.settings')
django.setup()

from payments.services import DecryptionService

# Your payload data
ciphertext = "8IXlQ8m+bB5ldQTXJ8FiOXZ8Nym7M2XzMpCxsp39dTQW0k5+68sUWQmRDiZCpImYpxX4P5YKXUXRnAZwLd1+Fckd4Nbc1BrXpCSxCpM238Fg9+k60VyQ7L79QWqIM9k0+VlbAMzn"
nonce = "Bgq0rNfiE24AaxvQWBlYLlmaun0IHF3j"
associated_data = "JOYPAY"

# You need to provide your App Secret Key here
# It should be 32 bytes (can be base64 encoded or raw)
ENCRYPTION_KEY = "YOUR_APP_SECRET_KEY_HERE"  # Replace with actual key

if __name__ == "__main__":
    print("Attempting to decrypt payload...")
    print(f"Nonce: {nonce}")
    print(f"Associated Data: {associated_data}")
    print(f"Ciphertext length: {len(ciphertext)} characters")
    print()
    
    if ENCRYPTION_KEY == "YOUR_APP_SECRET_KEY_HERE":
        print("ERROR: Please set ENCRYPTION_KEY in the script to your actual App Secret Key")
        print("\nThe encryption key should be:")
        print("- 32 bytes if raw")
        print("- Base64 encoded string (44 characters ending with =) if encoded")
        sys.exit(1)
    
    try:
        decrypted = DecryptionService.decrypt_ciphertext(
            ciphertext=ciphertext,
            encryption_key=ENCRYPTION_KEY,
            algorithm="AEAD_AES_256_GCM",
            nonce=nonce,
            associated_data=associated_data
        )
        
        print("✅ Successfully decrypted!")
        print("\nDecrypted data:")
        import json
        print(json.dumps(decrypted, indent=2))
        
    except Exception as e:
        print(f"❌ Decryption failed: {str(e)}")
        print(f"\nError type: {type(e).__name__}")

