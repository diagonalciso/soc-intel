"""
Compliance framework models.
NIST SP 800-53 Rev 5 security controls and NIST CSF 2.0 framework elements.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.db.postgres import Base


class NistControl(Base):
    """NIST SP 800-53 Rev 5 security control or control enhancement."""
    __tablename__ = "nist_controls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    control_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)  # e.g. "AC-1"
    family: Mapped[str] = mapped_column(String(10), nullable=False, index=True)   # e.g. "AC"
    family_name: Mapped[str] = mapped_column(String(100), nullable=False)          # e.g. "Access Control"
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enhancement: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[str | None] = mapped_column(String(20), nullable=True)      # parent control for enhancements
    baseline_impact: Mapped[list] = mapped_column(JSON, default=list)             # ["LOW","MODERATE","HIGH"]
    related: Mapped[list] = mapped_column(JSON, default=list)                     # related control IDs
    withdrawn: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CsfElement(Base):
    """NIST CSF 2.0 framework element — function, category, or subcategory."""
    __tablename__ = "csf_elements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    element_type: Mapped[str] = mapped_column(String(20), nullable=False)   # "function" | "category" | "subcategory"
    element_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)  # e.g. "GV", "GV.OC", "GV.OC-01"
    function_id: Mapped[str] = mapped_column(String(10), nullable=False, index=True)   # e.g. "GV"
    function_name: Mapped[str] = mapped_column(String(100), nullable=False)            # e.g. "GOVERN"
    category_id: Mapped[str | None] = mapped_column(String(20), nullable=True)        # e.g. "GV.OC" (None for functions)
    category_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
