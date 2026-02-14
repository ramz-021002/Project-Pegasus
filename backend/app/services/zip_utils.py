import pyzipper
import tempfile
from pathlib import Path
from typing import Optional

class ZipExtractor:
    @staticmethod
    def extract_zip(zip_path: Path, password: Optional[str] = None) -> Path:
        """
        Extracts the first file from a (possibly password-protected) zip archive.
        Returns the path to the extracted file.
        """
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            # Use the provided password if any
            pwd = password.encode() if password else None
            # Extract the first file (skip directories)
            for info in zf.infolist():
                if not info.is_dir():
                    with tempfile.NamedTemporaryFile(delete=False) as temp:
                        with zf.open(info.filename, pwd=pwd) as src:
                            temp.write(src.read())
                        return Path(temp.name)
            raise ValueError("No file found in zip archive.")

zip_extractor = ZipExtractor()
