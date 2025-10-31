import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
import logging

logger = logging.getLogger('payments')


class DecryptionService:
    """
    Service to handle decryption of SuperApp ciphertext
    """
    
    @staticmethod
    def decrypt_ciphertext(ciphertext, encryption_key, algorithm="AEAD_AES_256_GCM", nonce=None, associated_data=None):
        """
        Decrypt the ciphertext using the provided encryption key
        
        Args:
            ciphertext (str): Base64 encoded encrypted data
            encryption_key (str): The encryption key for this H5 app (32 bytes for AES-256)
            algorithm (str): Encryption algorithm (default: "AEAD_AES_256_GCM")
            nonce (str): Base64 encoded nonce (required for GCM)
            associated_data (str): Associated data string (required for GCM)
            
        Returns:
            dict: Decrypted payment data
        """
        try:
            if algorithm == "AEAD_AES_256_GCM":
                return DecryptionService._decrypt_aes256_gcm(
                    ciphertext, encryption_key, nonce, associated_data
                )
            else:
                # Fallback to Fernet for backward compatibility
                return DecryptionService._decrypt_fernet(ciphertext, encryption_key)
            
        except Exception as e:
            logger.error(f"Failed to decrypt ciphertext: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def _decrypt_aes256_gcm(ciphertext, encryption_key, nonce, associated_data):
        """
        Decrypt using AES-256-GCM algorithm
        
        Args:
            ciphertext (str): Base64 encoded encrypted data
            encryption_key (str): The encryption key (32 bytes)
            nonce (str): Base64 encoded nonce (12 bytes for GCM)
            associated_data (str): Associated data string
            
        Returns:
            dict: Decrypted payment data
        """
        try:
            # Decode the encryption key
            # If it's base64 encoded, decode it; otherwise use it directly as bytes
            if len(encryption_key) == 44 and encryption_key.endswith('='):
                # Likely base64 encoded 32-byte key
                key_bytes = base64.b64decode(encryption_key)
            else:
                # Try base64 decode first
                try:
                    key_bytes = base64.b64decode(encryption_key)
                    if len(key_bytes) != 32:
                        raise ValueError("Key must be 32 bytes after decoding")
                except:
                    # If not base64, treat as raw bytes or UTF-8 string
                    if isinstance(encryption_key, str):
                        key_bytes = encryption_key.encode('utf-8')
                        if len(key_bytes) != 32:
                            raise ValueError("Key must be 32 bytes. Provide base64 encoded key or ensure raw key is exactly 32 bytes")
                    else:
                        key_bytes = encryption_key
            
            if len(key_bytes) != 32:
                raise ValueError(f"Encryption key must be 32 bytes for AES-256. Got {len(key_bytes)} bytes")
            
            # Decode nonce (should be 12 bytes for GCM)
            if nonce:
                nonce_bytes = base64.b64decode(nonce)
                if len(nonce_bytes) != 12:
                    raise ValueError(f"Nonce must be 12 bytes for GCM. Got {len(nonce_bytes)} bytes")
            else:
                raise ValueError("Nonce is required for AES-256-GCM decryption")
            
            # Decode ciphertext
            ciphertext_bytes = base64.b64decode(ciphertext)
            
            # Convert associated_data to bytes if provided
            aad_bytes = associated_data.encode('utf-8') if associated_data else b''
            
            # Create AESGCM cipher and decrypt
            aesgcm = AESGCM(key_bytes)
            decrypted_bytes = aesgcm.decrypt(nonce_bytes, ciphertext_bytes, aad_bytes)
            
            # Parse JSON
            payment_data = json.loads(decrypted_bytes.decode('utf-8'))
            
            logger.info(f"Successfully decrypted payment data using AES-256-GCM")
            return payment_data
            
        except Exception as e:
            logger.error(f"Failed to decrypt using AES-256-GCM: {str(e)}")
            raise
    
    @staticmethod
    def _decrypt_fernet(ciphertext, encryption_key):
        """
        Decrypt using Fernet (legacy method for backward compatibility)
        
        Args:
            ciphertext (str): Base64 encoded encrypted data
            encryption_key (str): The encryption key for this H5 app
            
        Returns:
            dict: Decrypted payment data
        """
        try:
            # Convert encryption key to bytes
            key_bytes = encryption_key.encode('utf-8')
            
            # Derive a key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'salt',  # In production, use a proper salt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
            
            # Create Fernet cipher
            fernet = Fernet(key)
            
            # Decode base64 and decrypt
            encrypted_data = base64.b64decode(ciphertext)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Parse JSON
            payment_data = json.loads(decrypted_data.decode('utf-8'))
            
            logger.info(f"Successfully decrypted payment data using Fernet")
            return payment_data
            
        except Exception as e:
            logger.error(f"Failed to decrypt using Fernet: {str(e)}")
            raise
    
    @staticmethod
    def validate_payment_data(payment_data):
        """
        Validate the structure of decrypted payment data
        
        Args:
            payment_data (dict): Decrypted payment data
            
        Returns:
            bool: True if valid, raises exception if invalid
        """
        required_fields = ['payment_ref', 'amount', 'currency', 'status']
        
        for field in required_fields:
            if field not in payment_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate amount is numeric and positive
        try:
            amount = float(payment_data['amount'])
            if amount <= 0:
                raise ValueError("Amount must be positive")
        except (ValueError, TypeError):
            raise ValueError("Invalid amount format")
        
        # Validate currency is string
        if not isinstance(payment_data['currency'], str):
            raise ValueError("Currency must be a string")
        
        # Validate status
        valid_statuses = ['pending', 'processing', 'completed', 'failed', 'cancelled']
        if payment_data['status'] not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
        
        return True

