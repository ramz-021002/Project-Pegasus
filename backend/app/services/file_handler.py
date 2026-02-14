"""
File handling service for malware sample management.
Handles file quarantine, encryption, hashing, and validation.
"""
import hashlib
import logging
import magic
import os
import uuid
from pathlib import Path
from typing import Any, Tuple, Dict

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from app.config import settings

logger = logging.getLogger(__name__)


class FileHandler:
    """Handles secure file operations for malware samples."""

    def __init__(self):
        """Initialize file handler with encryption key."""
        self.upload_dir = settings.upload_dir
        self.encryption_key = self._derive_key(settings.encryption_key)
        self.fernet = Fernet(self.encryption_key)

        # Ensure upload directory exists
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def _derive_key(self, password: str) -> bytes:
        """
        Derive a Fernet encryption key from password using PBKDF2.

        Args:
            password: Password string to derive key from

        Returns:
            Base64-encoded 32-byte key suitable for Fernet
        """
        # Use a static salt for deterministic key derivation
        # In production, consider storing salt separately
        salt = b'project_pegasus_salt_v1'

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """
        Calculate SHA256, SHA1, and MD5 hashes of a file.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with sha256, sha1, and md5 keys
        """
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()

        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
                sha1_hash.update(chunk)
                md5_hash.update(chunk)

        return {
            "sha256": sha256_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "md5": md5_hash.hexdigest()
        }

    def get_file_type(self, file_path: Path) -> str:
        """
        Identify file type using magic bytes.

        Args:
            file_path: Path to file

        Returns:
            File type description string
        """
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(str(file_path))
            return file_type
        except Exception as e:
            logger.error(f"Error identifying file type: {e}")
            return "unknown"

    def validate_file(self, file_path: Path, original_filename: str) -> Tuple[bool, str]:
        """
        Validate uploaded file.

        Args:
            file_path: Path to the uploaded file
            original_filename: Original name of the uploaded file

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > settings.max_upload_size:
            return False, f"File size {file_size} exceeds maximum {settings.max_upload_size}"

        if file_size == 0:
            return False, "File is empty"

        # Check file extension (skip if empty string is in allowed list - means allow all)
        file_ext = Path(original_filename).suffix.lower()
        if settings.allowed_file_extensions and "" not in settings.allowed_file_extensions:
            if file_ext not in settings.allowed_file_extensions:
                return False, f"File extension {file_ext} not allowed"

        return True, ""

    def quarantine_file(self, source_path: Path, original_filename: str) -> Tuple[Path, str, Dict[str, str]]:
        """
        Move file to quarantine directory with encryption.

        Args:
            source_path: Path to source file
            original_filename: Original filename

        Returns:
            Tuple of (quarantine_path, encryption_key_id, hashes)
        """
        # Generate unique ID for this sample
        sample_id = str(uuid.uuid4())

        # Calculate hashes before encryption
        hashes = self.calculate_hashes(source_path)
        logger.info(f"Calculated hashes for {original_filename}: SHA256={hashes['sha256'][:16]}...")

        # Read file content
        with open(source_path, "rb") as f:
            file_content = f.read()

        # Encrypt file content
        encrypted_content = self.fernet.encrypt(file_content)

        # Create quarantine path
        quarantine_path = self.upload_dir / f"{sample_id}.encrypted"

        # Write encrypted file
        with open(quarantine_path, "wb") as f:
            f.write(encrypted_content)

        # Set strict file permissions (read-only for owner)
        try:
            os.chmod(quarantine_path, int(settings.file_permissions, 8))
        except Exception as e:
            logger.warning(f"Could not set file permissions: {e}")

        logger.info(f"File quarantined: {quarantine_path}")

        return quarantine_path, sample_id, hashes

    def decrypt_file(self, quarantine_path: Path, output_path: Path) -> None:
        """
        Decrypt a quarantined file for analysis.

        Args:
            quarantine_path: Path to encrypted file
            output_path: Path to write decrypted content
        """
        # Read encrypted content
        with open(quarantine_path, "rb") as f:
            encrypted_content = f.read()

        # Decrypt content
        decrypted_content = self.fernet.decrypt(encrypted_content)

        # Write decrypted file
        with open(output_path, "wb") as f:
            f.write(decrypted_content)

        logger.info(f"File decrypted to: {output_path}")

    def delete_quarantined_file(self, quarantine_path: Path) -> None:
        """
        Securely delete a quarantined file.

        Args:
            quarantine_path: Path to quarantined file
        """
        try:
            if quarantine_path.exists():
                # Overwrite file with random data before deletion
                file_size = quarantine_path.stat().st_size
                with open(quarantine_path, "wb") as f:
                    f.write(os.urandom(file_size))

                # Delete file
                quarantine_path.unlink()
                logger.info(f"Quarantined file deleted: {quarantine_path}")
        except Exception as e:
            logger.error(f"Error deleting quarantined file: {e}")

    def get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Get comprehensive file information.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with file information
        """
        hashes = self.calculate_hashes(file_path)
        file_type = self.get_file_type(file_path)
        file_size = file_path.stat().st_size

        return {
            **hashes,
            "file_type": file_type,
            "file_size": file_size
        }


# Singleton instance
file_handler = FileHandler()
