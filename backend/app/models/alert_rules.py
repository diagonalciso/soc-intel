"""
Alert rules model.
Defines conditions that auto-create alerts when matched by the scheduler.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, Integer, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.db.postgres import Base


class AlertRuleCondition(str, enum.Enum):
    new_ransomware_victim = "new_ransomware_victim"   # params: sector, country, group
    new_indicator = "new_indicator"                   # params: type, source, confidence_min
    new_malware = "new_malware"                       # params: name_contains
    new_threat_actor = "new_threat_actor"             # params: name_contains
    high_epss_cve = "high_epss_cve"                   # params: epss_min (0.0-1.0)
    cisa_kev_added = "cisa_kev_added"                 # params: (none — fires on any KEV add)
    credential_exposure = "credential_exposure"       # params: domain, exposure_type
    iab_listing = "iab_listing"                       # params: sector, country
    ioc_sighted = "ioc_sighted"                       # params: source


class AlertRuleSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    condition_type: Mapped[AlertRuleCondition] = mapped_column(SAEnum(AlertRuleCondition), nullable=False)
    condition_params: Mapped[dict] = mapped_column(JSON, default=dict)
    severity: Mapped[AlertRuleSeverity] = mapped_column(
        SAEnum(AlertRuleSeverity), default=AlertRuleSeverity.medium
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # Lookback window in minutes for dedup — don't re-fire within this window for same match
    dedup_window_minutes: Mapped[int] = mapped_column(Integer, default=60)
    matched_count: Mapped[int] = mapped_column(Integer, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
