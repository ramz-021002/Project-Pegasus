"""
Configuration management using pydantic-settings.
Loads settings from environment variables and .env file.
"""
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database Configuration
    database_url: str = Field(
        default="postgresql://pegasus:password@localhost:5432/pegasus_db",
        description="PostgreSQL connection string"
    )

    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string"
    )

    # Application Settings
    secret_key: str = Field(
        default="changeme",
        description="Secret key for session management"
    )
    debug: bool = Field(default=False, description="Enable debug mode")
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000"],
        description="CORS allowed origins"
    )

    # File Upload Settings
    upload_dir: Path = Field(
        default=Path("/tmp/pegasus/quarantine"),
        description="Directory for quarantine storage"
    )
    host_quarantine_path: str = Field(
        default="",
        description="Host path for quarantine volume (for Docker mounts)"
    )
    max_upload_size: int = Field(
        default=104857600,  # 100MB
        description="Maximum file upload size in bytes"
    )
    allowed_file_extensions: List[str] = Field(
        default=[
            # Executables
            ".exe", ".dll", ".sys", ".drv", ".scr", ".cpl", ".ocx", ".msi", ".com",
            # Linux/Unix
            ".elf", ".so", ".ko", ".sh", ".run", ".out", ".bin",
            # macOS
            ".app", ".dmg", ".pkg", ".dylib", ".bundle",
            # Scripts
            ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".py", ".pyc", ".pyw", ".rb", ".pl", ".php", ".lua",
            # Java/Android
            ".jar", ".class", ".apk", ".dex",
            # Documents (may contain macros/exploits)
            ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
            ".ppt", ".pptx", ".pptm", ".rtf", ".odt", ".ods", ".odp",
            # Archives
            ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso",
            # Web
            ".html", ".htm", ".hta", ".svg", ".swf",
            # Other
            ".lnk", ".url", ".inf", ".reg", ".chm",
            # Generic binary
            ""
        ],
        description="Allowed file extensions (empty string allows extensionless files)"
    )

    # Docker Configuration
    docker_socket: str = Field(
        default="unix:///var/run/docker.sock",
        description="Docker socket path"
    )
    analysis_timeout: int = Field(
        default=300,
        description="Container analysis timeout in seconds"
    )
    docker_network_prefix: str = Field(
        default="pegasus_analysis",
        description="Prefix for Docker network names"
    )

    # Security
    encryption_key: str = Field(
        default="changeme",
        description="Encryption key for file storage (32 bytes base64)"
    )
    file_permissions: str = Field(
        default="0400",
        description="File permissions for quarantined samples"
    )

    # Celery Configuration
    celery_broker_url: str = Field(
        default="redis://localhost:6379/0",
        description="Celery broker URL"
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/0",
        description="Celery result backend URL"
    )
    celery_task_track_started: bool = Field(
        default=True,
        description="Track task start events"
    )
    celery_task_time_limit: int = Field(
        default=600,
        description="Hard time limit for tasks in seconds"
    )

    # Analysis Settings
    static_analysis_image: str = Field(
        default="pegasus-static-analysis:latest",
        description="Docker image for static analysis"
    )
    dynamic_analysis_image: str = Field(
        default="pegasus-dynamic-analysis:latest",
        description="Docker image for dynamic analysis"
    )
    network_gateway_image: str = Field(
        default="pegasus-network-gateway:latest",
        description="Docker image for network gateway"
    )
    dynamic_execution_timeout: int = Field(
        default=30,
        description="Timeout for malware execution in seconds"
    )

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Path = Field(
        default=Path("/var/log/pegasus/app.log"),
        description="Log file path"
    )

    # Rate Limiting
    rate_limit_uploads: int = Field(
        default=5,
        description="Maximum uploads per window"
    )
    rate_limit_window: int = Field(
        default=3600,
        description="Rate limit window in seconds"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, v):
        """Parse comma-separated origins string into list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("allowed_file_extensions", mode="before")
    @classmethod
    def parse_extensions(cls, v):
        """Parse comma-separated extensions string into list."""
        if isinstance(v, str):
            return [ext.strip() for ext in v.split(",")]
        return v

    @field_validator("upload_dir", "log_file", mode="before")
    @classmethod
    def parse_path(cls, v):
        """Convert string paths to Path objects."""
        if isinstance(v, str):
            return Path(v)
        return v

    def validate_security(self) -> None:
        """Validate security-critical settings."""
        if self.secret_key == "changeme":
            raise ValueError("SECRET_KEY must be changed in production")
        if self.encryption_key == "changeme":
            raise ValueError("ENCRYPTION_KEY must be changed in production")
        if len(self.encryption_key) < 32:
            raise ValueError("ENCRYPTION_KEY must be at least 32 characters")


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Uses lru_cache to create a singleton pattern.
    """
    return Settings()


# Export settings instance
settings = get_settings()
