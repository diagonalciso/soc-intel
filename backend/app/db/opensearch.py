from opensearchpy import AsyncOpenSearch
from app.config import get_settings

settings = get_settings()

_client: AsyncOpenSearch | None = None


def get_opensearch() -> AsyncOpenSearch:
    global _client
    if _client is None:
        _client = AsyncOpenSearch(
            hosts=[settings.opensearch_host],
            use_ssl=False,
            verify_certs=False,
        )
    return _client


# Index names
STIX_INDEX = "socint-stix"
INDICATORS_INDEX = "socint-indicators"
DARKWEB_INDEX = "socint-darkweb"


STIX_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "type": {"type": "keyword"},
            "spec_version": {"type": "keyword"},
            "created": {"type": "date"},
            "modified": {"type": "date"},
            "name": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}},
            },
            "description": {"type": "text"},
            "labels": {"type": "keyword"},
            "confidence": {"type": "integer"},
            "lang": {"type": "keyword"},
            "revoked": {"type": "boolean"},
            "object_marking_refs": {"type": "keyword"},
            "created_by_ref": {"type": "keyword"},
            "x_opencti_score": {"type": "integer"},
            "x_clawint_source": {"type": "keyword"},
            "x_clawint_darkweb": {"type": "boolean"},
            "x_clawint_source_reliability": {"type": "integer"},
            "x_clawint_last_sighted": {"type": "date"},
            "x_clawint_sighting_count": {"type": "integer"},
            "x_clawint_fp_candidate": {"type": "boolean"},
            "tlp": {"type": "keyword"},
        }
    },
    "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 0,
    },
}

DARKWEB_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "type": {"type": "keyword"},
            "created": {"type": "date"},
            "modified": {"type": "date"},
            "source": {"type": "keyword"},
            "group_name": {"type": "keyword"},
            "victim_name": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword"}},
            },
            "victim_domain": {"type": "keyword"},
            "country": {"type": "keyword"},
            "sector": {"type": "keyword"},
            "date_posted": {"type": "date"},
            "email": {"type": "keyword"},
            "domain": {"type": "keyword"},
            "malware_family": {"type": "keyword"},
            "access_type": {"type": "keyword"},
            "forum_name": {"type": "keyword"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}


async def ensure_indices():
    client = get_opensearch()
    for index, mapping in [
        (STIX_INDEX, STIX_INDEX_MAPPING),
        (DARKWEB_INDEX, DARKWEB_INDEX_MAPPING),
    ]:
        exists = await client.indices.exists(index=index)
        if not exists:
            await client.indices.create(index=index, body=mapping)
