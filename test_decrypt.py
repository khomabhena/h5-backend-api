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

# Your payload data - UPDATE THESE VALUES
ciphertext = "aqOynDI0gLzK80cN9OCvID9lFQ08Md7HQvQMwLi6q0boWkWvTCz3MrI3x7EISAcc1fOn4guNkYurVG7td/QtijJ9JFm/DlxnfXU45hz9zPyW09zdF1TbiPzUQPFKwOwU8V7WkVFfpcfgkH5yrP9yzxHOY3FF2aBxdBElsQIbMZDEjEKXVLd9UVAHqzPRAHmDplzSEHO1jL3Ro4oydekp47Y/X0ftsD6sRDuXS3mVwo2t0JEsKg1+OrUrGFg0P47fYujqNmaV+0EPB6nrs5KwlbGzYR34m/keLiY6NP2isC0g3xdDkHRdgOZ5YLzbVQKhWxaxtd6TqGvHW0rx7caDAJzD1VdO3eBDy9ldl1DEe3e2lr9NB+H1fgvipeuPdTKJM8sCN/caZmNcEFWePoOkecSmYkva72XkCQMJP9fdJpY7AvAhS+GSuBagGHMjoRKsaBnf0SbZjH0ag8KzYavb5Py+/CU3EZ1CZu1FfoukIHWvEaLL585xQHgSScdq9RhE73FltIWo9z/q44FQj3DTitAnMe6Ce9K9rYL4q7MXPi6IVFbZtzmdSIUyYdsk4JIo30FeNvhRzVjvmet9IVQWYhUCJCbqnQ=="
nonce = "YOUR_NONCE_HERE"  # Replace with the nonce from your payload
associated_data = "JOYPAY"  # Usually "JOYPAY" based on API docs

# You need to provide your App Secret Key here
# It should be 32 bytes (can be base64 encoded or raw)
ENCRYPTION_KEY = "YOUR_APP_SECRET_KEY_HERE"  # Replace with actual key from H5App

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

