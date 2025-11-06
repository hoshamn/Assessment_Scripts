"""
Secure Credential Manager for Microsoft Logs AI Analyzer

Handles secure storage and retrieval of API keys and sensitive credentials.
Supports multiple storage backends: Windows DPAPI, encrypted files, environment variables.
"""

import os
import sys
import base64
import json
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

# Import Windows DPAPI if available
try:
    if sys.platform == 'win32':
        import win32crypt
        DPAPI_AVAILABLE = True
    else:
        DPAPI_AVAILABLE = False
except ImportError:
    DPAPI_AVAILABLE = False


class CredentialManager:
    """Manages secure storage and retrieval of credentials"""

    def __init__(self, storage_method: str = 'auto', config_dir: Path = None):
        """
        Initialize credential manager

        Args:
            storage_method: Storage method ('dpapi', 'encrypted_file', 'environment', 'auto')
            config_dir: Directory for storing credential files
        """
        self.config_dir = config_dir or Path('./config')
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Determine storage method
        if storage_method == 'auto':
            if DPAPI_AVAILABLE:
                self.storage_method = 'dpapi'
            else:
                self.storage_method = 'encrypted_file'
        else:
            self.storage_method = storage_method

        # Initialize encryption key for file-based storage
        self._encryption_key = None
        if self.storage_method == 'encrypted_file':
            self._init_encryption_key()

        self.credentials_file = self.config_dir / '.credentials.enc'

    def _init_encryption_key(self):
        """Initialize or load encryption key for file-based storage"""
        key_file = self.config_dir / '.key'

        if key_file.exists():
            # Load existing key
            with open(key_file, 'rb') as f:
                self._encryption_key = f.read()
        else:
            # Generate new key from machine-specific data
            # In production, consider using a more robust key derivation
            machine_id = self._get_machine_id()
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'msloganalyzer_salt_v1',  # In production, use random salt
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
            self._encryption_key = key

            # Save key (with restricted permissions)
            with open(key_file, 'wb') as f:
                f.write(self._encryption_key)

            # Set restrictive permissions on Windows
            if sys.platform == 'win32':
                self._set_file_permissions_windows(key_file)

    def _get_machine_id(self) -> str:
        """Get a machine-specific identifier"""
        if sys.platform == 'win32':
            # Use Windows machine GUID
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography",
                    0,
                    winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                )
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return machine_guid
            except:
                pass

        # Fallback to hostname
        import socket
        return socket.gethostname()

    def _set_file_permissions_windows(self, file_path: Path):
        """Set restrictive file permissions on Windows"""
        if sys.platform == 'win32':
            try:
                import win32security
                import ntsecuritycon as con

                # Get current user SID
                user_sid = win32security.GetTokenInformation(
                    win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY),
                    win32security.TokenUser
                )[0]

                # Create DACL with only owner access
                dacl = win32security.ACL()
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                    user_sid
                )

                # Set security descriptor
                sd = win32security.SECURITY_DESCRIPTOR()
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    str(file_path),
                    win32security.DACL_SECURITY_INFORMATION,
                    sd
                )
            except:
                pass  # Fail silently if permissions can't be set

    def store_credential(self, key: str, value: str) -> bool:
        """
        Store a credential securely

        Args:
            key: Credential identifier
            value: Credential value

        Returns:
            True if successful
        """
        try:
            if self.storage_method == 'dpapi':
                return self._store_dpapi(key, value)
            elif self.storage_method == 'encrypted_file':
                return self._store_encrypted_file(key, value)
            elif self.storage_method == 'environment':
                return self._store_environment(key, value)
            else:
                raise ValueError(f"Unsupported storage method: {self.storage_method}")
        except Exception as e:
            print(f"Error storing credential: {e}")
            return False

    def retrieve_credential(self, key: str) -> Optional[str]:
        """
        Retrieve a credential

        Args:
            key: Credential identifier

        Returns:
            Credential value or None if not found
        """
        try:
            if self.storage_method == 'dpapi':
                return self._retrieve_dpapi(key)
            elif self.storage_method == 'encrypted_file':
                return self._retrieve_encrypted_file(key)
            elif self.storage_method == 'environment':
                return self._retrieve_environment(key)
            else:
                raise ValueError(f"Unsupported storage method: {self.storage_method}")
        except Exception as e:
            print(f"Error retrieving credential: {e}")
            return None

    def delete_credential(self, key: str) -> bool:
        """
        Delete a credential

        Args:
            key: Credential identifier

        Returns:
            True if successful
        """
        try:
            if self.storage_method == 'dpapi':
                return self._delete_dpapi(key)
            elif self.storage_method == 'encrypted_file':
                return self._delete_encrypted_file(key)
            elif self.storage_method == 'environment':
                return self._delete_environment(key)
            else:
                raise ValueError(f"Unsupported storage method: {self.storage_method}")
        except Exception as e:
            print(f"Error deleting credential: {e}")
            return False

    def list_credentials(self) -> list:
        """List all stored credential keys"""
        try:
            if self.storage_method == 'dpapi':
                return self._list_dpapi()
            elif self.storage_method == 'encrypted_file':
                return self._list_encrypted_file()
            elif self.storage_method == 'environment':
                return self._list_environment()
            else:
                return []
        except:
            return []

    # DPAPI methods (Windows only)
    def _store_dpapi(self, key: str, value: str) -> bool:
        """Store credential using Windows DPAPI"""
        if not DPAPI_AVAILABLE:
            raise RuntimeError("DPAPI not available on this platform")

        encrypted = win32crypt.CryptProtectData(
            value.encode('utf-8'),
            f"MSLogAnalyzer_{key}",
            None,
            None,
            None,
            0
        )

        cred_file = self.config_dir / f'.cred_{key}.dat'
        with open(cred_file, 'wb') as f:
            f.write(encrypted)

        self._set_file_permissions_windows(cred_file)
        return True

    def _retrieve_dpapi(self, key: str) -> Optional[str]:
        """Retrieve credential using Windows DPAPI"""
        if not DPAPI_AVAILABLE:
            raise RuntimeError("DPAPI not available on this platform")

        cred_file = self.config_dir / f'.cred_{key}.dat'
        if not cred_file.exists():
            return None

        with open(cred_file, 'rb') as f:
            encrypted = f.read()

        try:
            _, decrypted = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)
            return decrypted.decode('utf-8')
        except:
            return None

    def _delete_dpapi(self, key: str) -> bool:
        """Delete credential stored with DPAPI"""
        cred_file = self.config_dir / f'.cred_{key}.dat'
        if cred_file.exists():
            cred_file.unlink()
            return True
        return False

    def _list_dpapi(self) -> list:
        """List credentials stored with DPAPI"""
        return [
            f.stem.replace('.cred_', '')
            for f in self.config_dir.glob('.cred_*.dat')
        ]

    # Encrypted file methods
    def _store_encrypted_file(self, key: str, value: str) -> bool:
        """Store credential in encrypted file"""
        # Load existing credentials
        credentials = self._load_credentials_file()

        # Add/update credential
        credentials[key] = value

        # Save encrypted
        cipher = Fernet(self._encryption_key)
        encrypted_data = cipher.encrypt(json.dumps(credentials).encode('utf-8'))

        with open(self.credentials_file, 'wb') as f:
            f.write(encrypted_data)

        # Set restrictive permissions
        if sys.platform == 'win32':
            self._set_file_permissions_windows(self.credentials_file)

        return True

    def _retrieve_encrypted_file(self, key: str) -> Optional[str]:
        """Retrieve credential from encrypted file"""
        credentials = self._load_credentials_file()
        return credentials.get(key)

    def _delete_encrypted_file(self, key: str) -> bool:
        """Delete credential from encrypted file"""
        credentials = self._load_credentials_file()
        if key in credentials:
            del credentials[key]

            # Save updated credentials
            cipher = Fernet(self._encryption_key)
            encrypted_data = cipher.encrypt(json.dumps(credentials).encode('utf-8'))

            with open(self.credentials_file, 'wb') as f:
                f.write(encrypted_data)

            return True
        return False

    def _list_encrypted_file(self) -> list:
        """List credentials in encrypted file"""
        credentials = self._load_credentials_file()
        return list(credentials.keys())

    def _load_credentials_file(self) -> Dict[str, str]:
        """Load and decrypt credentials file"""
        if not self.credentials_file.exists():
            return {}

        try:
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()

            cipher = Fernet(self._encryption_key)
            decrypted_data = cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except:
            return {}

    # Environment variable methods
    def _store_environment(self, key: str, value: str) -> bool:
        """Store credential as environment variable (not persistent)"""
        env_key = f"MSLOG_{key.upper()}"
        os.environ[env_key] = value
        return True

    def _retrieve_environment(self, key: str) -> Optional[str]:
        """Retrieve credential from environment variable"""
        env_key = f"MSLOG_{key.upper()}"
        return os.environ.get(env_key)

    def _delete_environment(self, key: str) -> bool:
        """Delete environment variable"""
        env_key = f"MSLOG_{key.upper()}"
        if env_key in os.environ:
            del os.environ[env_key]
            return True
        return False

    def _list_environment(self) -> list:
        """List credentials in environment variables"""
        prefix = "MSLOG_"
        return [
            key[len(prefix):].lower()
            for key in os.environ.keys()
            if key.startswith(prefix)
        ]


def get_credential_manager(config: Dict[str, Any] = None) -> CredentialManager:
    """
    Factory function to get configured credential manager

    Args:
        config: Configuration dictionary

    Returns:
        CredentialManager instance
    """
    storage_method = 'auto'
    config_dir = Path('./config')

    if config:
        storage_method = config.get('security', {}).get('credential_storage', 'auto')
        config_dir = Path(config.get('general', {}).get('data_directory', './data'))

    return CredentialManager(storage_method=storage_method, config_dir=config_dir)
