"""
Quick decrypt script for the provided payload
"""
import os
import sys
import django
import json

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'h5_backend_api.settings')
django.setup()

from payments.services import DecryptionService

# Your payload data
ciphertext = 'aqOynDI0gLzK80cN9OCvID9lFQ08Md7HQvQMwLi6q0boWkWvTCz3MrI3x7EISAcc1fOn4guNkYurVG7td/QtijJ9JFm/DlxnfXU45hz9zPyW09zdF1TbiPzUQPFKwOwU8V7WkVFfpcfgkH5yrP9yzxHOY3FF2aBxdBElsQIbMZDEjEKXVLd9UVAHqzPRAHmDplzSEHO1jL3Ro4oydekp47Y/X0ftsD6sRDuXS3mVwo2t0JEsKg1+OrUrGFg0P47fYujqNmaV+0EPB6nrs5KwlbGzYR34m/keLiY6NP2isC0g3xdDkHRdgOZ5YLzbVQKhWxaxtd6TqGvHW0rx7caDAJzD1VdO3eBDy9ldl1DEe3e2lr9NB+H1fgvipeuPdTKJM8sCN/caZmNcEFWePoOkecSmYkva72XkCQMJP9fdJpY7AvAhS+GSuBagGHMjoRKsaBnf0SbZjH0ag8KzYavb5Py+/CU3EZ1CZu1FfoukIHWvEaLL585xQHgSScdq9RhE73FltIWo9z/q44FQj3DTitAnMe6Ce9K9rYL4q7MXPi6IVFbZtzmdSIUyYdsk4JIo30FeNvhRzVjvmet9IVQWYhUCJCbqnQ=='
nonce = 'o03LNzVcH3AQrNEX3Qb3pvuhGN25vBFl'
associated_data = 'JOYPAY'

# Try to get encryption key from H5App database
try:
    from payments.models import H5App
    app = H5App.objects.get(app_key='HUbbFjH2VZ')
    encryption_key = app.encryption_key
    print(f"✅ Found H5App: {app.name}")
    print(f"   Encryption key length: {len(encryption_key)} characters")
except H5App.DoesNotExist:
    print("❌ H5App with app_key 'HUbbFjH2VZ' not found in database.")
    print("\nPlease either:")
    print("1. Create the H5App in the database with app_key='HUbbFjH2VZ' and your encryption_key")
    print("2. Or manually set ENCRYPTION_KEY below and run this script")
    encryption_key = None
    # UNCOMMENT AND SET YOUR KEY HERE:
    # encryption_key = "YOUR_APP_SECRET_KEY_HERE"

if encryption_key:
    print(f"\n{'='*60}")
    print("DECRYPTION ATTEMPT")
    print(f"{'='*60}")
    print(f"Ciphertext length: {len(ciphertext)} chars")
    print(f"Nonce: {nonce}")
    print(f"Associated Data: {associated_data}")
    print(f"Algorithm: AEAD_AES_256_GCM")
    print(f"{'='*60}\n")
    
    try:
        decrypted = DecryptionService.decrypt_ciphertext(
            ciphertext=ciphertext,
            encryption_key=encryption_key,
            algorithm="AEAD_AES_256_GCM",
            nonce=nonce,
            associated_data=associated_data
        )
        
        print("✅ SUCCESSFULLY DECRYPTED!")
        print(f"\n{'='*60}")
        print("DECRYPTED DATA:")
        print(f"{'='*60}")
        print(json.dumps(decrypted, indent=2, ensure_ascii=False))
        print(f"\n{'='*60}")
        
    except Exception as e:
        print(f"❌ DECRYPTION FAILED: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print("\nFull traceback:")
        traceback.print_exc()
else:
    print("\n⚠️  Cannot decrypt without encryption key.")

