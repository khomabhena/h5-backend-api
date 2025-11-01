import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger('payments')


class DecryptionService:
    """
    Service to handle decryption of SuperApp ciphertext
    Following decrypt.js implementation line by line
    """
    
    # Constants from decrypt.js
    KEY = "4tmvsbJaVBQPFxsum+c3lA=="  # Line 4: const key = Buffer.from("4tmvsbJaVBQPFxsum+c3lA==", 'utf8');
    NONCE = "Ft5MhFp5iMJMzGLaCWiTV5UxpK3gKGIz"  # Line 5: const nonce = "Ft5MhFp5iMJMzGLaCWiTV5UxpK3gKGIz";
    ASSOCIATED_DATA = "JOYPAY"  # Line 6: const associatedData = "JOYPAY";
    CIPHERTEXT = "m9maVw9vds55U4ZMp9b1T2QgNPmJalmYc2b3BgV2yJJzDskFdqnyP7zeweBosF90YJOaCtwi+R0Bdnu+YM1gST2/vgNWzvTiLxgtLsYvfoFjC7m8ZnLBqQ/uBwK3TOzV8XdJ/HTCv32A2ZLiW8URt4K+bu5fHQ7NNuiAyZ+tHuHziu3oHuEhDQWAtxWSeUDdAG9hA/1tgx1J1mMOz+j86hwNywhVy8wOUiQej3cUv8cAtqjxSLkQRYZsTNmyjC4Ktk+33sqaqcIW6EsvgoLIkARmuDUEM8SVzYpwcUnD6zE5kDFkIlI1k7BPihBQUm+wDHb7qg/6ajVrCjIElI0uN4ESqznS5AT9ZYpKulflIl2EcDQMUk4thAS+Y+gg5sw0hDzy2xYUO23CodwZBnxa8Q3k8yDFarVbk8rS9EnrMXHEDSrP/flLUhE3UnYHWczV7/AHbXa85V6uyyyqCV2WC1YR9ksJDS+ANOmRkSSqKes796N+SsQYQyQDdNlN25cHs70FGkxOZX/Af7WwViq2zp1HHrhCUhfNH4JIfpqddbYSE8MOkT99zUHe+WwXfvp3FRs0IOyijxxNYodRol+2hYgTh+DLIz4="  # Line 7: const ciphertextBase64 = "...";
    
    @staticmethod
    def decrypt_ciphertext(ciphertext=None, encryption_key=None, algorithm="AEAD_AES_192_GCM", nonce=None, associated_data=None):
        """
        Decrypt the ciphertext using the provided encryption key
        Matches decrypt.js implementation
        
        Args:
            ciphertext: Base64 encoded encrypted data (defaults to CIPHERTEXT constant from decrypt.js)
            encryption_key: The encryption key (defaults to KEY constant from decrypt.js)
            algorithm: Encryption algorithm (default: "AEAD_AES_192_GCM")
            nonce: Nonce string (defaults to NONCE constant from decrypt.js)
            associated_data: Associated data string (defaults to ASSOCIATED_DATA constant from decrypt.js)
            
        Returns:
            dict: Decrypted payment data
        """
        # Use defaults from decrypt.js if not provided
        # ciphertext_val = ciphertext if ciphertext else DecryptionService.CIPHERTEXT
        ciphertext_val = DecryptionService.CIPHERTEXT
        key = encryption_key if encryption_key else DecryptionService.KEY
        nonce_val = nonce if nonce else DecryptionService.NONCE
        aad = associated_data if associated_data else DecryptionService.ASSOCIATED_DATA
        
        try:
            # Step 1: Prepare the key - Line 4: const key = Buffer.from("4tmvsbJaVBQPFxsum+c3lA==", 'utf8');
            # This treats the string as literal UTF-8, NOT base64
            key_bytes = key.encode('utf-8')
            
            # Step 2: Prepare the nonce - Line 11: Buffer.from(nonce, 'utf8')
            nonce_bytes = nonce_val.encode('utf-8')
            
            # Step 3: Prepare associated data - Line 14: Buffer.from(associatedData, 'utf8')
            aad_bytes = aad.encode('utf-8')
            
            # Step 4: Decode ciphertext from base64 - Line 17: Buffer.from(ciphertextBase64, 'base64')
            ciphertext_buffer = base64.b64decode(ciphertext_val)
            
            # Step 5: Extract auth tag - Line 18: ciphertextBuffer.slice(ciphertextBuffer.length - 16)
            auth_tag = ciphertext_buffer[-16:]
            
            # Step 6: Extract encrypted data - Line 19: ciphertextBuffer.slice(0, ciphertextBuffer.length - 16)
            encrypted = ciphertext_buffer[:-16]
            
            # Step 7: Create decipher - Line 11: crypto.createDecipheriv('aes-192-gcm', key, Buffer.from(nonce, 'utf8'))
            # Python's AESGCM handles 24-byte keys as AES-192 automatically
            aesgcm = AESGCM(key_bytes)
            
            # Step 8: Combine encrypted + auth tag for Python's AESGCM
            # Python's AESGCM.decrypt expects ciphertext with auth tag at the end
            ciphertext_with_tag = encrypted + auth_tag
            
            # Step 9: Decrypt - Line 23: Buffer.concat([decipher.update(encrypted), decipher.final()])
            # Python does this in one call
            decrypted_bytes = aesgcm.decrypt(nonce_bytes, ciphertext_with_tag, aad_bytes)
            
            # Step 10: Parse JSON - Line 25: decrypted.toString('utf8')
            decrypted_text = decrypted_bytes.decode('utf-8')
            payment_data = json.loads(decrypted_text)
            
            logger.info(f"Successfully decrypted payment data using {algorithm}")
            return payment_data
            
        except Exception as e:
            logger.error(f"Failed to decrypt ciphertext: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            raise ValueError(f"Decryption failed: {str(e)}")
