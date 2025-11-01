"""
Payment Result Decryption Service
Based on Java implementation from official documentation
Matches the Java code pattern exactly:
- AES/GCM/NoPadding
- GCMParameterSpec with 128-bit auth tag
- UTF-8 encoded nonce and associated data
- Base64 decoded ciphertext
"""
import json
import base64
import logging

logger = logging.getLogger('payments')

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad
    except ImportError:
        AES = None
        unpad = None
        logger.error("PyCryptodome or pycryptodomex is required. Install with: pip install pycryptodome")


class JavaDecryptionService:
    """
    Decryption service following the Java documentation pattern exactly.
    
    Java Implementation:
    ```java
    String decrypt(String associatedData, String nonce, String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
            2, // DECRYPT_MODE
            new SecretKeySpec("your app secret key", "AES"),
            new GCMParameterSpec(128, nonce.getBytes(StandardCharsets.UTF_8))
        );
        if (associatedData != null) {
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
        }
        return new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)), StandardCharsets.UTF_8);
    }
    ```
    """
    
    @staticmethod
    def decrypt(associated_data, nonce, ciphertext, encryption_key):
        """
        Decrypt payment result ciphertext following Java documentation pattern exactly.
        
        This matches the Java code:
        - Uses AES/GCM/NoPadding (automatically determined by PyCryptodome based on key length)
        - GCMParameterSpec(128, nonce.getBytes(StandardCharsets.UTF_8)) - 128-bit auth tag
        - Associated data as UTF-8 bytes
        - Base64 decode ciphertext then decrypt
        
        Args:
            associated_data (str): Associated data string (can be None)
            nonce (str): Nonce string (UTF-8 encoded)
            ciphertext (str): Base64 encoded ciphertext
            encryption_key (str): Encryption key (as string, will be converted to bytes)
            
        Returns:
            str: Decrypted JSON string
            
        Raises:
            ImportError: If PyCryptodome is not installed
            ValueError: If decryption fails
        """
        if AES is None:
            raise ImportError(
                "PyCryptodome is required. Install with: pip install pycryptodome"
            )
        
        try:
            # Step 1: Prepare the key
            # Java: new SecretKeySpec("your app secret key", "AES")
            # Convert string key to bytes (UTF-8 encoding, like Java's SecretKeySpec)
            if isinstance(encryption_key, str):
                key = encryption_key.encode('utf-8')
            else:
                key = encryption_key
            
            logger.info(f"Key length: {len(key)} bytes (AES-192 requires 24 bytes, AES-256 requires 32 bytes)")
            
            # Step 2: Prepare nonce - UTF-8 encoded
            # Java: nonce.getBytes(StandardCharsets.UTF_8)
            nonce_bytes = nonce.encode('utf-8')
            logger.info(f"Nonce length: {len(nonce_bytes)} bytes")
            
            # Step 3: Base64 decode ciphertext
            # Java: Base64.getDecoder().decode(ciphertext)
            ciphertext_bytes = base64.b64decode(ciphertext)
            logger.info(f"Ciphertext bytes length: {len(ciphertext_bytes)} bytes")
            
            # Step 4: Create AES cipher in GCM mode
            # Java: Cipher.getInstance("AES/GCM/NoPadding")
            # Java: new GCMParameterSpec(128, nonce_bytes) - 128-bit (16-byte) auth tag
            # PyCryptodome: AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
            # The nonce parameter sets the IV and PyCryptodome uses 16-byte auth tag by default
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
            
            # Step 5: Update with associated data (if provided)
            # Java: cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8))
            if associated_data:
                aad_bytes = associated_data.encode('utf-8')
                cipher.update(aad_bytes)
                logger.info(f"Associated data length: {len(aad_bytes)} bytes")
            
            # Step 6: Decrypt and verify
            # Java: cipher.doFinal(Base64.getDecoder().decode(ciphertext))
            # doFinal() decrypts and verifies the auth tag in one operation
            # PyCryptodome's decrypt() automatically extracts and verifies the 16-byte auth tag from the end
            decrypted = cipher.decrypt(ciphertext_bytes)
            
            # Step 7: Convert to UTF-8 string
            # Java: new String(..., StandardCharsets.UTF_8)
            logger.info(f"Decrypted bytes length: {len(decrypted)} bytes")
            
            # Try to decode as UTF-8
            try:
                decrypted_str = decrypted.decode('utf-8')
            except UnicodeDecodeError as e:
                # Log the problematic bytes for debugging
                logger.error(f"UTF-8 decode failed at position {e.start}: {e.reason}")
                logger.error(f"Problematic bytes (hex): {decrypted[max(0, e.start-10):e.start+10].hex()}")
                logger.error(f"First 100 bytes (hex): {decrypted[:100].hex()}")
                raise ValueError(
                    f"Decrypted data is not valid UTF-8. "
                    f"This usually means wrong key, nonce, or associated_data. "
                    f"Error: {str(e)}"
                )
            
            logger.info("Successfully decrypted payment data using Java pattern")
            return decrypted_str
            
        except Exception as e:
            logger.error(f"Failed to decrypt ciphertext using Java pattern: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_to_dict(associated_data, nonce, ciphertext, encryption_key):
        """
        Convenience method that decrypts and parses JSON to dict.
        
        Args:
            associated_data (str): Associated data string (can be None)
            nonce (str): Nonce string
            ciphertext (str): Base64 encoded ciphertext
            encryption_key (str): Encryption key
            
        Returns:
            dict: Decrypted and parsed payment data
        """
        decrypted_str = JavaDecryptionService.decrypt(
            associated_data, nonce, ciphertext, encryption_key
        )
        return json.loads(decrypted_str)

