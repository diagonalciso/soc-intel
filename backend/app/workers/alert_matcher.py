"""
Alert rule matcher.
Runs on a schedule to check alert rules against recent intelligence
and creates alerts in PostgreSQL when conditions are matched.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.db.opensearch import get_opensearch, STIX_INDEX, DARKWEB_INDEX
from app.db.postgres import AsyncSessionLocal
from app.models.alert_rules import AlertRule, AlertRuleCondition
from app.models.cases import Alert, CaseSeverity
from sqlalchemy import select

logger = logging.getLogger(__name__)

# How far back to look for new objects when matching rules (in minutes)
DEFAULT_LOOKBACK_MINUTES = 65


async def run_alert_matcher():
    """Main entry point for the scheduler. Loads rules and matches each one."""
    async with AsyncSessionLocal() as db:
        stmt = select(AlertRule).where(AlertRule.enabled == True)
        rules = (await db.execute(stmt)).scalars().all()

    if not rules:
        return

    logger.info(f"AlertMatcher: checking {len(rules)} enabled rules")
    matched_total = 0

    for rule in rules:
        try:
            alerts_created = await _match_rule(rule)
            matched_total += alerts_created
        except Exception as e:
            logger.error(f"AlertMatcher: rule [{rule.name}] error: {e}")

    if matched_total:
        logger.info(f"AlertMatcher: created {matched_total} alerts")


async def check_rule_matches(rule: AlertRule, dry_run: bool = False) -> int:
    """Check how many objects currently match a rule. Used by the test endpoint."""
    return await _count_matches(rule)


async def _match_rule(rule: AlertRule) -> int:
    """Evaluate one rule and create alerts for new matches."""
    lookback = DEFAULT_LOOKBACK_MINUTES
    since = (
        datetime.now(timezone.utc) - timedelta(minutes=lookback)
    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    objects = await _fetch_matches(rule, since)
    if not objects:
        return 0

    alerts_created = 0
    async with AsyncSessionLocal() as db:
        for obj in objects[:20]:  # cap at 20 alerts per rule per run
            alert_title = _make_title(rule, obj)
            alert = Alert(
                title=alert_title,
                description=_make_description(rule, obj),
                source=f"alert-rule:{rule.condition_type}",
                severity=CaseSeverity(rule.severity.value),
                status="new",
                raw_data={
                    "rule_id": str(rule.id),
                    "rule_name": rule.name,
                    "matched_object": obj,
                },
            )
            db.add(alert)
            alerts_created += 1

        if alerts_created:
            rule.matched_count = (rule.matched_count or 0) + alerts_created
            rule.last_matched_at = datetime.now(timezone.utc)
            db.add(rule)

        await db.commit()

    return alerts_created


async def _fetch_matches(rule: AlertRule, since: str) -> list[dict]:
    """Fetch objects from OpenSearch that match the rule condition."""
    params = rule.condition_params or {}
    client = get_opensearch()

    if rule.condition_type == AlertRuleCondition.new_ransomware_victim:
        return await _match_ransomware_victim(client, params, since)

    if rule.condition_type == AlertRuleCondition.new_indicator:
        return await _match_new_indicator(client, params, since)

    if rule.condition_type == AlertRuleCondition.new_malware:
        return await _match_new_stix_type(client, "malware", params.get("name_contains"), since)

    if rule.condition_type == AlertRuleCondition.new_threat_actor:
        return await _match_new_stix_type(client, "threat-actor", params.get("name_contains"), since)

    if rule.condition_type == AlertRuleCondition.high_epss_cve:
        return await _match_high_epss(client, params, since)

    if rule.condition_type == AlertRuleCondition.cisa_kev_added:
        return await _match_cisa_kev(client, since)

    if rule.condition_type == AlertRuleCondition.credential_exposure:
        return await _match_credential_exposure(client, params, since)

    if rule.condition_type == AlertRuleCondition.iab_listing:
        return await _match_iab_listing(client, params, since)

    if rule.condition_type == AlertRuleCondition.ioc_sighted:
        return await _match_ioc_sighted(client, params, since)

    return []


async def _count_matches(rule: AlertRule) -> int:
    objects = await _fetch_matches(rule, since="2000-01-01T00:00:00.000Z")
    return len(objects)


async def _match_ransomware_victim(client, params: dict, since: str) -> list[dict]:
    must = [
        {"term": {"type": "ransomware-leak"}},
        {"range": {"created": {"gte": since}}},
    ]
    if params.get("sector"):
        must.append({"match": {"sector": params["sector"]}})
    if params.get("country"):
        must.append({"match": {"country": params["country"]}})
    if params.get("group"):
        must.append({"match": {"group_name": params["group"]}})

    resp = await client.search(
        index=DARKWEB_INDEX,
        body={"query": {"bool": {"must": must}}, "size": 20},
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_new_indicator(client, params: dict, since: str) -> list[dict]:
    must: list[dict] = [
        {"term": {"type": "indicator"}},
        {"range": {"created": {"gte": since}}},
    ]
    if params.get("source"):
        must.append({"term": {"x_clawint_source": params["source"]}})
    if params.get("confidence_min"):
        must.append({"range": {"confidence": {"gte": params["confidence_min"]}}})

    resp = await client.search(
        index=STIX_INDEX,
        body={"query": {"bool": {"must": must}}, "size": 20},
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_new_stix_type(client, stix_type: str, name_contains: str | None, since: str) -> list[dict]:
    must: list[dict] = [
        {"term": {"type": stix_type}},
        {"range": {"created": {"gte": since}}},
    ]
    if name_contains:
        must.append({"match": {"name": name_contains}})

    resp = await client.search(
        index=STIX_INDEX,
        body={"query": {"bool": {"must": must}}, "size": 20},
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_high_epss(client, params: dict, since: str) -> list[dict]:
    epss_min = params.get("epss_min", 0.5)
    resp = await client.search(
        index=STIX_INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type": "vulnerability"}},
                        {"range": {"created": {"gte": since}}},
                        {"range": {"x_clawint_epss_score": {"gte": epss_min}}},
                    ]
                }
            },
            "size": 20,
        },
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_cisa_kev(client, since: str) -> list[dict]:
    resp = await client.search(
        index=STIX_INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type": "vulnerability"}},
                        {"term": {"x_clawint_source": "cisa-kev"}},
                        {"range": {"created": {"gte": since}}},
                    ]
                }
            },
            "size": 20,
        },
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_credential_exposure(client, params: dict, since: str) -> list[dict]:
    must: list[dict] = [
        {"term": {"type": "credential-exposure"}},
        {"range": {"created": {"gte": since}}},
    ]
    if params.get("domain"):
        must.append({"match": {"domain": params["domain"]}})
    if params.get("exposure_type"):
        must.append({"term": {"exposure_type": params["exposure_type"]}})

    resp = await client.search(
        index=DARKWEB_INDEX,
        body={"query": {"bool": {"must": must}}, "size": 20},
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_iab_listing(client, params: dict, since: str) -> list[dict]:
    must: list[dict] = [
        {"term": {"type": "iab-listing"}},
        {"range": {"created": {"gte": since}}},
    ]
    if params.get("sector"):
        must.append({"match": {"target_sector": params["sector"]}})
    if params.get("country"):
        must.append({"match": {"target_country": params["country"]}})

    resp = await client.search(
        index=DARKWEB_INDEX,
        body={"query": {"bool": {"must": must}}, "size": 20},
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


async def _match_ioc_sighted(client, params: dict, since: str) -> list[dict]:
    must: list[dict] = [
        {"term": {"type": "sighting"}},
        {"range": {"created": {"gte": since}}},
    ]
    if params.get("source"):
        must.append({"match": {"where_sighted_refs": params["source"]}})

    resp = await client.search(
        index=STIX_INDEX,
        body={"query": {"bool": {"must": must}}, "size": 20},
    )
    return [h["_source"] for h in resp["hits"]["hits"]]


def _make_title(rule: AlertRule, obj: dict) -> str:
    name = obj.get("name") or obj.get("victim_name") or obj.get("id", "")[:16]
    return f"[{rule.condition_type.value.replace('_', ' ').title()}] {name[:100]}"


def _make_description(rule: AlertRule, obj: dict) -> str:
    lines = [f"Alert rule: {rule.name}"]
    if obj.get("name"):
        lines.append(f"Object: {obj['name']}")
    if obj.get("victim_name"):
        lines.append(f"Victim: {obj['victim_name']}")
    if obj.get("description"):
        lines.append(f"Description: {obj['description'][:200]}")
    if obj.get("group_name"):
        lines.append(f"Group: {obj['group_name']}")
    if obj.get("x_clawint_source"):
        lines.append(f"Source: {obj['x_clawint_source']}")
    return "\n".join(lines)
