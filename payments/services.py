import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
import logging

logger = logging.getLogger('payments')


class DecryptionService:
    """
    Service to handle decryption of SuperApp ciphertext
    """
    
    @staticmethod
    def decrypt_ciphertext(ciphertext, encryption_key):
        """
        Decrypt the ciphertext using the provided encryption key
        
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
            
            logger.info(f"Successfully decrypted payment data: {payment_data}")
            return payment_data
            
        except Exception as e:
            logger.error(f"Failed to decrypt ciphertext: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")
    
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

