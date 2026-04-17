from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    app_name: str = "SOCINT"
    app_env: str = "development"
    secret_key: str = "change-me"
    connector_api_key: str = "change-me-connector-key"
    taxii_extra_servers: str = ""  # "name|url|user|pass,name2|url2|user2|pass2"
    allowed_origins: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "socint"
    postgres_user: str = "socint"
    postgres_password: str = "socint"

    @property
    def postgres_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_url_sync(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # OpenSearch
    opensearch_host: str = "http://localhost:9200"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = "socint"

    @property
    def redis_url(self) -> str:
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/0"

    # RabbitMQ
    rabbitmq_host: str = "localhost"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "socint"
    rabbitmq_pass: str = "socint"

    @property
    def rabbitmq_url(self) -> str:
        return f"amqp://{self.rabbitmq_user}:{self.rabbitmq_pass}@{self.rabbitmq_host}:{self.rabbitmq_port}/"

    # MinIO
    minio_endpoint: str = "localhost:9000"
    minio_root_user: str = "socint"
    minio_root_password: str = "socint123"
    minio_bucket: str = "socint"

    # Tor
    tor_proxy: str = "socks5://localhost:9050"

    # Connector API keys
    otx_api_key: str = ""
    nvd_api_key: str = ""   # optional — boosts NVD rate limit from 5→50 req/30s
    virustotal_api_key: str = ""
    shodan_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    greynoise_api_key: str = ""
    abuseipdb_api_key: str = ""
    hudsonrock_api_key: str = ""
    hibp_api_key: str = ""
    criminal_ip_api_key: str = ""
    pulsedive_api_key: str = ""
    flare_api_key: str = ""
    darkowl_api_key: str = ""
    recorded_future_api_key: str = ""
    intel471_username: str = ""
    intel471_api_key: str = ""
    vulncheck_api_key: str = ""
    urlscan_api_key: str = ""
    hybrid_analysis_api_key: str = ""
    malpedia_api_key: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
