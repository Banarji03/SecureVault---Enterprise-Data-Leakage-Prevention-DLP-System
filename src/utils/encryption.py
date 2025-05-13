import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path

logger = logging.getLogger(__name__)

class EncryptionManager:
    _instance = None
    _key = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EncryptionManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize encryption key"""
        try:
            key_file = Path('config/encryption.key')
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self._key = f.read()
            else:
                self._key = Fernet.generate_key()
                key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(self._key)
            
            self.fernet = Fernet(self._key)
            logger.info("Encryption manager initialized")
        except Exception as e:
            logger.error(f"Error initializing encryption: {e}")
            raise

    def encrypt_text(self, text: str) -> str:
        """Encrypt text data"""
        try:
            encrypted_data = self.fernet.encrypt(text.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Error encrypting text: {e}")
            return text

    def decrypt_text(self, encrypted_text: str) -> str:
        """Decrypt text data"""
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Error decrypting text: {e}")
            return encrypted_text

    def encrypt_file(self, file_path: str) -> bool:
        """Encrypt a file"""
        try:
            file_path = Path(file_path)
            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted_data = self.fernet.encrypt(file_data)
            
            # Save encrypted file with .encrypted extension
            encrypted_path = file_path.with_suffix(file_path.suffix + '.encrypted')
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # Remove original file
            file_path.unlink()
            logger.info(f"File encrypted successfully: {file_path}")
            return True

        except Exception as e:
            logger.error(f"Error encrypting file {file_path}: {e}")
            return False

    def decrypt_file(self, encrypted_file_path: str) -> bool:
        """Decrypt a file"""
        try:
            encrypted_path = Path(encrypted_file_path)
            if not encrypted_path.suffix.endswith('.encrypted'):
                logger.error(f"File is not encrypted: {encrypted_file_path}")
                return False

            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Save decrypted file without .encrypted extension
            decrypted_path = encrypted_path.with_suffix(''.join(encrypted_path.suffixes[:-1]))
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)

            # Remove encrypted file
            encrypted_path.unlink()
            logger.info(f"File decrypted successfully: {encrypted_file_path}")
            return True

        except Exception as e:
            logger.error(f"Error decrypting file {encrypted_file_path}: {e}")
            return False

# Global encryption manager instance
_encryption_manager = None

def get_encryption_manager() -> EncryptionManager:
    """Get the global encryption manager instance"""
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager

def encrypt_data(data: str) -> str:
    """Encrypt text data using the global encryption manager"""
    return get_encryption_manager().encrypt_text(data)

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt text data using the global encryption manager"""
    return get_encryption_manager().decrypt_text(encrypted_data)

def encrypt_file(file_path: str) -> bool:
    """Encrypt a file using the global encryption manager"""
    return get_encryption_manager().encrypt_file(file_path)

def decrypt_file(file_path: str) -> bool:
    """Decrypt a file using the global encryption manager"""
    return get_encryption_manager().decrypt_file(file_path)