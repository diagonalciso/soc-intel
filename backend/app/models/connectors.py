import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum
from app.db.postgres import Base


class ConnectorType(str, enum.Enum):
    import_external = "import_external"
    import_internal = "import_internal"
    enrichment = "enrichment"
    stream = "stream"
    export = "export"


class ConnectorStatus(str, enum.Enum):
    active = "active"
    inactive = "inactive"
    error = "error"
    running = "running"


class Connector(Base):
    __tablename__ = "connectors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    connector_type: Mapped[ConnectorType] = mapped_column(SAEnum(ConnectorType))
    status: Mapped[ConnectorStatus] = mapped_column(SAEnum(ConnectorStatus), default=ConnectorStatus.inactive)

    # Configuration (stored encrypted in prod)
    config: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Scheduling (cron expression for import connectors)
    schedule: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Stats
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_run_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    objects_imported: Mapped[int | None] = mapped_column(default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
