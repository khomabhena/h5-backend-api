"""
Test script to decrypt using the JS-style AES-192-GCM method
"""
import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'h5_backend_api.settings')
django.setup()

from payments.services import DecryptionService
import json

# Test data from decrypt.js
ciphertext = "m9maVw9vds55U4ZMp9b1T2QgNPmJalmYc2b3BgV2yJJzDskFdqnyP7zeweBosF90YJOaCtwi+R0Bdnu+YM1gST2/vgNWzvTiLxgtLsYvfoFjC7m8ZnLBqQ/uBwK3TOzV8XdJ/HTCv32A2ZLiW8URt4K+bu5fHQ7NNuiAyZ+tHuHziu3oHuEhDQWAtxWSeUDdAG9hA/1tgx1J1mMOz+j86hwNywhVy8wOUiQej3cUv8cAtqjxSLkQRYZsTNmyjC4Ktk+33sqaqcIW6EsvgoLIkARmuDUEM8SVzYpwcUnD6zE5kDFkIlI1k7BPihBQUm+wDHb7qg/6ajVrCjIElI0uN4ESqznS5AT9ZYpKulflIl2EcDQMUk4thAS+Y+gg5sw0hDzy2xYUO23CodwZBnxa8Q3k8yDFarVbk8rS9EnrMXHEDSrP/flLUhE3UnYHWczV7/AHbXa85V6uyyyqCV2WC1YR9ksJDS+ANOmRkSSqKes796N+SsQYQyQDdNlN25cHs70FGkxOZX/Af7WwViq2zp1HHrhCUhfNH4JIfpqddbYSE8MOkT99zUHe+WwXfvp3FRs0IOyijxxNYodRol+2hYgTh+DLIz4="
nonce = "Ft5MhFp5iMJMzGLaCWiTV5UxpK3gKGIz"
associated_data = "JOYPAY"
encryption_key = "4tmvsbJaVBQPFxsum+c3lA=="  # This is the literal UTF-8 string (not base64 decoded)

if __name__ == "__main__":
    print("Testing AES-192-GCM decryption (JS-style)...")
    print(f"Key (UTF-8 length): {len(encryption_key.encode('utf-8'))} bytes")
    print(f"Nonce: {nonce}")
    print(f"Nonce (UTF-8 length): {len(nonce.encode('utf-8'))} bytes")
    print(f"Associated Data: {associated_data}")
    print(f"Ciphertext length: {len(ciphertext)} chars")
    print()
    
    try:
        decrypted = DecryptionService.decrypt_ciphertext(
            ciphertext=ciphertext,
            encryption_key=encryption_key,
            algorithm="AEAD_AES_192_GCM",
            nonce=nonce,
            associated_data=associated_data
        )
        
        print("✅ SUCCESSFULLY DECRYPTED!")
        print("\nDecrypted data:")
        print(json.dumps(decrypted, indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"❌ DECRYPTION FAILED: {str(e)}")
        import traceback
        traceback.print_exc()

