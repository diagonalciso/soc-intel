"""
Detection rules model — YARA, Sigma, Snort/Suricata, STIX Patterns.
"""
import uuid
import enum
from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey, Enum as SAEnum, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.db.postgres import Base


class RuleType(str, enum.Enum):
    yara         = "yara"
    sigma        = "sigma"
    snort        = "snort"
    suricata     = "suricata"
    stix_pattern = "stix-pattern"


class RuleStatus(str, enum.Enum):
    active      = "active"
    testing     = "testing"
    deprecated  = "deprecated"


class RuleSeverity(str, enum.Enum):
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str]             = mapped_column(String(255), nullable=False)
    rule_type: Mapped[RuleType]   = mapped_column(SAEnum(RuleType), nullable=False)
    content: Mapped[str]          = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    author: Mapped[str | None]    = mapped_column(String(255), nullable=True)
    tags: Mapped[list]            = mapped_column(JSON, default=list)
    severity: Mapped[RuleSeverity] = mapped_column(
        SAEnum(RuleSeverity), nullable=False, default=RuleSeverity.medium
    )
    status: Mapped[RuleStatus]    = mapped_column(
        SAEnum(RuleStatus), nullable=False, default=RuleStatus.active
    )
    # STIX object IDs this rule detects (threat actors, malware, campaigns, etc.)
    linked_stix_ids: Mapped[list] = mapped_column(JSON, default=list)
    # MITRE ATT&CK technique IDs covered by this rule (e.g. ["T1566", "T1059.001"])
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    # NIST SP 800-53 Rev 5 control IDs this rule satisfies (e.g. ["AC-2", "SI-3"])
    nist_800_53: Mapped[list] = mapped_column(JSON, default=list)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime]  = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime]  = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
