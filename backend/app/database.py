"""Database models and connection management."""
import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column, String, Integer, DateTime, Enum, ForeignKey, Text, Index, TIMESTAMP, BigInteger
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings

# Base class for all models
Base = declarative_base()


class SampleStatus(enum.Enum):
    """Status of malware sample analysis."""
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisType(enum.Enum):
    """Type of analysis performed."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    NETWORK = "network"


class AnalysisStatus(enum.Enum):
    """Status of individual analysis task."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class IndicatorType(enum.Enum):
    """Type of network indicator."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"


class Sample(Base):
    """Malware sample metadata and tracking."""
    __tablename__ = "samples"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sha256 = Column(String(64), nullable=False, index=True, unique=True)
    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    file_type = Column(String(255), nullable=True)
    original_filename = Column(Text, nullable=False)
    upload_timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    encryption_key_id = Column(String(64), nullable=False)
    status = Column(Enum(SampleStatus), nullable=False, default=SampleStatus.PENDING)

    # Relationships
    analysis_results = relationship("AnalysisResult", back_populates="sample", cascade="all, delete-orphan")
    network_indicators = relationship("NetworkIndicator", back_populates="sample", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Sample(id={self.id}, sha256={self.sha256[:16]}..., status={self.status})>"


class AnalysisResult(Base):
    """Results from individual analysis tasks."""
    __tablename__ = "analysis_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sample_id = Column(UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    analysis_type = Column(Enum(AnalysisType), nullable=False)
    started_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    completed_at = Column(TIMESTAMP, nullable=True)
    status = Column(Enum(AnalysisStatus), nullable=False, default=AnalysisStatus.RUNNING)
    results_json = Column(JSONB, nullable=True)
    container_id = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    sample = relationship("Sample", back_populates="analysis_results")

    # Indexes
    __table_args__ = (
        Index('idx_sample_analysis', 'sample_id', 'analysis_type'),
        Index('idx_status', 'status'),
    )

    def __repr__(self):
        return f"<AnalysisResult(id={self.id}, type={self.analysis_type}, status={self.status})>"


class NetworkIndicator(Base):
    """Network indicators extracted from malware analysis."""
    __tablename__ = "network_indicators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sample_id = Column(UUID(as_uuid=True), ForeignKey("samples.id", ondelete="CASCADE"), nullable=False)
    indicator_type = Column(Enum(IndicatorType), nullable=False)
    value = Column(Text, nullable=False)
    first_seen = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    confidence = Column(Integer, nullable=True, default=100)
    context = Column(Text, nullable=True)

    # Relationships
    sample = relationship("Sample", back_populates="network_indicators")

    # Indexes
    __table_args__ = (
        Index('idx_indicator_value', 'value'),
        Index('idx_indicator_type', 'indicator_type'),
        Index('idx_sample_indicators', 'sample_id', 'indicator_type'),
    )

    def __repr__(self):
        return f"<NetworkIndicator(id={self.id}, type={self.indicator_type}, value={self.value})>"


# Database engine and session
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=settings.debug
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """
    Dependency for FastAPI to get database session.
    Yields a session and ensures it's closed after request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Initialize database tables.
    Creates all tables defined in Base metadata.
    """
    Base.metadata.create_all(bind=engine)


def drop_db() -> None:
    """
    Drop all database tables.
    WARNING: This deletes all data!
    """
    Base.metadata.drop_all(bind=engine)


# Database operations helper functions
class DatabaseOperations:
    """Helper class for common database operations."""

    @staticmethod
    def create_sample(db: Session, **kwargs) -> Sample:
        """Create a new sample record."""
        sample = Sample(**kwargs)
        db.add(sample)
        db.commit()
        db.refresh(sample)
        return sample

    @staticmethod
    def get_sample_by_sha256(db: Session, sha256: str) -> Optional[Sample]:
        """Get sample by SHA256 hash."""
        return db.query(Sample).filter(Sample.sha256 == sha256).first()

    @staticmethod
    def get_sample_by_id(db: Session, sample_id: uuid.UUID) -> Optional[Sample]:
        """Get sample by ID."""
        return db.query(Sample).filter(Sample.id == sample_id).first()

    @staticmethod
    def update_sample_status(db: Session, sample_id: uuid.UUID, status: SampleStatus) -> None:
        """Update sample status."""
        db.query(Sample).filter(Sample.id == sample_id).update({"status": status})
        db.commit()

    @staticmethod
    def create_analysis_result(db: Session, **kwargs) -> AnalysisResult:
        """Create a new analysis result record."""
        result = AnalysisResult(**kwargs)
        db.add(result)
        db.commit()
        db.refresh(result)
        return result

    @staticmethod
    def update_analysis_result(
        db: Session,
        result_id: uuid.UUID,
        status: AnalysisStatus,
        results_json: Optional[dict] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update analysis result."""
        update_data = {
            "status": status,
            "completed_at": datetime.utcnow()
        }
        if results_json:
            update_data["results_json"] = results_json
        if error_message:
            update_data["error_message"] = error_message

        db.query(AnalysisResult).filter(AnalysisResult.id == result_id).update(update_data)
        db.commit()

    @staticmethod
    def create_network_indicator(db: Session, **kwargs) -> NetworkIndicator:
        """Create a network indicator record."""
        indicator = NetworkIndicator(**kwargs)
        db.add(indicator)
        db.commit()
        db.refresh(indicator)
        return indicator

    @staticmethod
    def get_all_samples(db: Session, limit: int = 100, offset: int = 0):
        """Get all samples with pagination."""
        return db.query(Sample).order_by(Sample.upload_timestamp.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_indicators_for_sample(db: Session, sample_id: uuid.UUID):
        """Get all network indicators for a sample."""
        return db.query(NetworkIndicator).filter(NetworkIndicator.sample_id == sample_id).all()
