import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, DateTime, Integer, Boolean, Text, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from .db import Base


def _uuid():
    return str(uuid.uuid4())


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    reporter_pseudonym = Column(String(128), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="pending")
    current_commitment = Column(String(66), nullable=False)
    canonical_nonce = Column(String(64), nullable=False)
    indicators_json = Column(JSONB, nullable=False, default=dict)
    campaign_summary = Column(Text, nullable=True)
    incident_summary = Column(Text, nullable=True)
    evidence_refs_json = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    revisions = relationship("ReportRevision", back_populates="report", cascade="all, delete-orphan")
    disputes = relationship("ReportDispute", back_populates="report", cascade="all, delete-orphan")
    validations = relationship("ReportValidation", back_populates="report", cascade="all, delete-orphan")
    onchain_refs = relationship("OnchainRef", back_populates="report", cascade="all, delete-orphan")


class ReportRevision(Base):
    __tablename__ = "report_revisions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    report_id = Column(UUID(as_uuid=False), ForeignKey("threat_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    commitment = Column(String(66), nullable=False)
    version = Column(Integer, nullable=False)
    tx_hash = Column(String(66), nullable=True)
    block_number = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    report = relationship("ThreatReport", back_populates="revisions")


class ReportDispute(Base):
    __tablename__ = "report_disputes"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    report_id = Column(UUID(as_uuid=False), ForeignKey("threat_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    disputant = Column(String(128), nullable=True)
    reason_hash = Column(String(66), nullable=False)
    tx_hash = Column(String(66), nullable=True)
    block_number = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    report = relationship("ThreatReport", back_populates="disputes")


class ReportValidation(Base):
    __tablename__ = "report_validations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    report_id = Column(UUID(as_uuid=False), ForeignKey("threat_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    validator = Column(String(128), nullable=True)
    verdict = Column(Boolean, nullable=False)
    tx_hash = Column(String(66), nullable=True)
    block_number = Column(Integer, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    report = relationship("ThreatReport", back_populates="validations")


class OnchainRef(Base):
    __tablename__ = "onchain_refs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    report_id = Column(UUID(as_uuid=False), ForeignKey("threat_reports.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)
    tx_hash = Column(String(66), nullable=False)
    block_number = Column(Integer, nullable=True)
    contract_address = Column(String(42), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    report = relationship("ThreatReport", back_populates="onchain_refs")


Index("ix_threat_reports_status", ThreatReport.status)
Index("ix_threat_reports_created", ThreatReport.created_at)