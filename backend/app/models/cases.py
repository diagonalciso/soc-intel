import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, ForeignKey, Enum as SAEnum, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY
import enum
from app.db.postgres import Base


class CaseSeverity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class CaseStatus(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    pending = "pending"
    resolved = "resolved"
    closed = "closed"


class TaskStatus(str, enum.Enum):
    waiting = "waiting"
    in_progress = "in_progress"
    completed = "completed"
    cancelled = "cancelled"


class ObservableType(str, enum.Enum):
    ipv4 = "ipv4-addr"
    ipv6 = "ipv6-addr"
    domain = "domain-name"
    url = "url"
    file_hash_md5 = "file:hashes.MD5"
    file_hash_sha1 = "file:hashes.SHA-1"
    file_hash_sha256 = "file:hashes.SHA-256"
    email = "email-addr"
    mac = "mac-addr"
    registry_key = "windows-registry-key"
    user_account = "user-account"
    autonomous_system = "autonomous-system"


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[CaseSeverity] = mapped_column(SAEnum(CaseSeverity), default=CaseSeverity.medium)
    status: Mapped[CaseStatus] = mapped_column(SAEnum(CaseStatus), default=CaseStatus.open)
    tags: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # TLP marking
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")

    # Assignment
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )

    # Linked STIX objects (stored as IDs referencing OpenSearch)
    stix_refs: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Compliance tagging
    nist_800_53: Mapped[list | None] = mapped_column(JSON, nullable=True)  # e.g. ["AC-2", "IR-4"]
    csf_tags: Mapped[list | None] = mapped_column(JSON, nullable=True)     # e.g. ["DE.AE-08", "RS.MA-03"]

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # SLA
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    tasks: Mapped[list["CaseTask"]] = relationship(back_populates="case", cascade="all, delete-orphan")
    observables: Mapped[list["Observable"]] = relationship(back_populates="case", cascade="all, delete-orphan")
    comments: Mapped[list["CaseComment"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class CaseTask(Base):
    __tablename__ = "case_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[TaskStatus] = mapped_column(SAEnum(TaskStatus), default=TaskStatus.waiting)
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    case: Mapped[Case] = relationship(back_populates="tasks")


class Observable(Base):
    __tablename__ = "observables"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"))
    type: Mapped[ObservableType] = mapped_column(SAEnum(ObservableType))
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    enrichment_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    stix_id: Mapped[str | None] = mapped_column(String(255), nullable=True)  # linked STIX object
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped[Case] = relationship(back_populates="observables")


class CaseComment(Base):
    __tablename__ = "case_comments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"))
    author_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped[Case] = relationship(back_populates="comments")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # connector name
    severity: Mapped[CaseSeverity] = mapped_column(SAEnum(CaseSeverity), default=CaseSeverity.medium)
    status: Mapped[str] = mapped_column(String(50), default="new")  # new, triaged, escalated, dismissed
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    promoted_to_case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
