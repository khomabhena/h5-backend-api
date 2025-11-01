"""
Payment Result Decryption Service
Based on official documentation for AES-GCM decryption
Following the Python example from the Parameter Decrypt documentation
"""
import json
import base64
import logging

logger = logging.getLogger('payments')

try:
    from Crypto.Cipher import AES
except ImportError:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        AES = None
        logger.error("PyCryptodome or pycryptodomex is required. Install with: pip install pycryptodome")


class DocumentationDecryptionService:
    """
    Decryption service following the official documentation pattern.
    
    Documentation Steps:
    1. Get the application's key introduced while merchant register, and record it as 'key'.
    2. Get the algorithm described in resource.algorithm (currently AEAD_AES_256_GCM), 
       resource.nonce and resource.associated_data.
    3. Decrypt resource.ciphertext with 'key', 'nonce' and 'associated_data' to Get a 
       resource object in JSON form.
    """
    
    @staticmethod
    def decrypt(associated_data, nonce, ciphertext, encryption_key):
        """
        Decrypt payment result ciphertext following official documentation pattern.
        
        This matches the Python sample code from the documentation:
        - Uses Crypto.Cipher.AES with MODE_GCM
        - Handles AES-192-GCM (24-byte key) or AES-256-GCM (32-byte key) automatically
        - UTF-8 encodes associated_data and nonce
        - Base64 decodes ciphertext
        - Returns decrypted JSON as string (which can be parsed to dict)
        
        Args:
            associated_data (str): Associated data string (e.g., "JOYPAY")
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
            # Documentation shows: key = b'your app secret key'
            # Convert string key to bytes (UTF-8 encoding)
            if isinstance(encryption_key, str):
                key = encryption_key.encode('utf-8')
            else:
                key = encryption_key
            
            logger.info(f"Key length: {len(key)} bytes (AES-192 requires 24 bytes, AES-256 requires 32 bytes)")
            
            # Step 2: Prepare nonce - UTF-8 encoded as shown in documentation
            nonce_bytes = nonce.encode('utf-8')
            logger.info(f"Nonce length: {len(nonce_bytes)} bytes")
            
            # Step 3: Base64 decode ciphertext - as shown in documentation
            # JavaScript: const ciphertextBuffer = Buffer.from(ciphertextBase64, 'base64');
            ciphertext_bytes = base64.b64decode(ciphertext)
            logger.info(f"Ciphertext bytes length: {len(ciphertext_bytes)} bytes")
            
            # Step 4: Create AES cipher in GCM mode
            # Documentation shows: cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
            # PyCryptodome automatically determines AES-192 vs AES-256 based on key length
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
            
            # Step 5: Update with associated data (if provided)
            # Documentation shows: cipher.update(associatedData.encode('utf-8'))
            # Note: In PyCryptodome, AAD must be set BEFORE decryption
            if associated_data:
                aad_bytes = associated_data.encode('utf-8')
                cipher.update(aad_bytes)
                logger.info(f"Associated data length: {len(aad_bytes)} bytes")
            
            # Step 6: Decrypt
            # Documentation shows: decrypted = cipher.decrypt(ciphertext_bytes)
            # PyCryptodome's decrypt() automatically extracts and verifies the 16-byte auth tag from the end
            # The ciphertext_bytes should have the encrypted data + 16-byte auth tag at the end
            try:
                decrypted = cipher.decrypt(ciphertext_bytes)
            except ValueError as e:
                # If auth tag verification fails, try extracting tag manually and using decrypt_and_verify
                logger.warning(f"Standard decrypt failed: {str(e)}, trying decrypt_and_verify method")
                if len(ciphertext_bytes) < 16:
                    raise ValueError(f"Ciphertext too short: {len(ciphertext_bytes)} bytes")
                auth_tag = ciphertext_bytes[-16:]
                encrypted_data = ciphertext_bytes[:-16]
                
                # Recreate cipher for decrypt_and_verify
                cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
                if associated_data:
                    cipher2.update(associated_data.encode('utf-8'))
                decrypted = cipher2.decrypt_and_verify(encrypted_data, auth_tag)
            
            # Step 7: Decode to UTF-8 string
            # Documentation shows: decrypted.decode('utf-8')
            logger.info(f"Decrypted bytes length: {len(decrypted)} bytes")
            logger.info(f"First 50 bytes (hex): {decrypted[:50].hex() if len(decrypted) > 50 else decrypted.hex()}")
            
            # Try to decode as UTF-8, with error handling
            try:
                decrypted_str = decrypted.decode('utf-8')
            except UnicodeDecodeError as e:
                # Log the problematic bytes for debugging
                logger.error(f"UTF-8 decode failed at position {e.start}: {e.reason}")
                logger.error(f"Problematic bytes (hex): {decrypted[max(0, e.start-10):e.start+10].hex()}")
                # Try to decode with error handling to see partial result
                decrypted_str = decrypted.decode('utf-8', errors='replace')
                logger.warning(f"Decoded with replacement characters - original data may be corrupted or wrong key/nonce/AAD used")
                raise ValueError(f"Decrypted data is not valid UTF-8. This usually means wrong key, nonce, or associated_data. Error: {str(e)}")
            
            logger.info("Successfully decrypted payment data using documentation method")
            return decrypted_str
            
        except Exception as e:
            logger.error(f"Failed to decrypt ciphertext using documentation method: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_to_dict(associated_data, nonce, ciphertext, encryption_key):
        """
        Convenience method that decrypts and parses JSON to dict.
        
        Args:
            associated_data (str): Associated data string
            nonce (str): Nonce string
            ciphertext (str): Base64 encoded ciphertext
            encryption_key (str): Encryption key
            
        Returns:
            dict: Decrypted and parsed payment data
        """
        decrypted_str = DocumentationDecryptionService.decrypt(
            associated_data, nonce, ciphertext, encryption_key
        )
        return json.loads(decrypted_str)

