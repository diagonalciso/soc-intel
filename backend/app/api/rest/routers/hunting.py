"""
Hunting workbench router — cross-datasource threat hunting queries.
Correlates IOCs → TTPs → actors → detection rules.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Path
from sqlalchemy import select

from app.auth.dependencies import get_current_user
from app.core.stix_engine import STIXEngine, get_stix_engine
from app.db.postgres import AsyncSessionLocal
from app.models.rules import DetectionRule, RuleType

router = APIRouter(prefix="/hunting", tags=["hunting"])


@router.get("/pivot")
async def hunting_pivot(
    q: str = Query(..., min_length=1, max_length=500, description="Search term: IOC, actor, family, or technique"),
    size: int = Query(20, ge=5, le=100, description="Result limit per type"),
    user=Depends(get_current_user),
    stix_engine: STIXEngine = Depends(get_stix_engine),
):
    """
    Pivot search: IOCs + correlated Sigma rules + YARA rules + threat actors.
    Returns unified hunting results across all intel types.
    """
    result = {
        "query": q,
        "stix_objects": [],
        "sigma_rules": [],
        "yara_rules": [],
        "threat_actors": [],
        "malware_families": [],
    }

    try:
        # Step 1: pivot search across STIX objects
        pivot_results = await stix_engine.pivot_search(q, size=size)
        result["stix_objects"] = pivot_results

        # Extract technique IDs and malware families from results for correlation
        techniques = set()
        families = set()
        for obj in pivot_results:
            # Extract MITRE ATT&CK techniques from labels or names
            if obj.get("type") == "attack-pattern":
                techniques.add(obj.get("name", ""))
            # Extract malware family references
            if "malware" in obj.get("labels", []):
                families.add(obj.get("name", ""))
            if "x_clawint_malware_families" in obj:
                malware_list = obj.get("x_clawint_malware_families", [])
                if isinstance(malware_list, list):
                    families.update(malware_list)
            # Extract threat actors
            if obj.get("type") == "threat-actor":
                result["threat_actors"].append(obj)

        # Step 2: find related Sigma rules
        if techniques or families:
            async with AsyncSessionLocal() as db:
                sigma_stmt = select(DetectionRule).where(
                    DetectionRule.rule_type == RuleType.sigma
                ).limit(size)
                sigma_result = await db.execute(sigma_stmt)
                sigma_rules = sigma_result.scalars().all()

                # Filter rules by technique overlap
                matching_sigma = []
                for rule in sigma_rules:
                    rule_techs = set(rule.mitre_techniques) if rule.mitre_techniques else set()
                    if rule_techs & techniques:
                        matching_sigma.append({
                            "id": rule.id,
                            "name": rule.name,
                            "severity": rule.severity.value if rule.severity else "medium",
                            "techniques": list(rule_techs),
                        })

                result["sigma_rules"] = matching_sigma[:size]

                # Step 3: find related YARA rules
                yara_stmt = select(DetectionRule).where(
                    DetectionRule.rule_type == RuleType.yara
                ).limit(size * 2)
                yara_result = await db.execute(yara_stmt)
                yara_rules = yara_result.scalars().all()

                # Filter rules by family tags
                matching_yara = []
                for rule in yara_rules:
                    rule_tags = set(rule.tags) if rule.tags else set()
                    # Lowercase comparison for tag matching
                    rule_tags_lower = {t.lower() for t in rule_tags}
                    families_lower = {f.lower() for f in families}
                    if rule_tags_lower & families_lower:
                        matching_yara.append({
                            "id": rule.id,
                            "name": rule.name,
                            "severity": rule.severity.value if rule.severity else "medium",
                            "tags": list(rule_tags),
                        })

                result["yara_rules"] = matching_yara[:size]

        # Step 4: find malware families mentioned
        if families:
            malware_search = await stix_engine.search(
                stix_type="malware",
                query=list(families)[0] if families else q,
                size=size,
            )
            result["malware_families"] = malware_search.get("objects", [])[:size]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Hunting query failed: {str(e)}",
        )

    return result


@router.get("/malware-families")
async def list_malware_families(
    q: str = Query("", max_length=500, description="Optional filter by name"),
    from_: int = Query(0, ge=0, alias="from", description="Pagination offset"),
    size: int = Query(100, ge=5, le=500, description="Result limit"),
    user=Depends(get_current_user),
    stix_engine: STIXEngine = Depends(get_stix_engine),
):
    """List and search malware families from all sources (MalwareBazaar, Ransomware.live, Hybrid Analysis, etc.), sorted alphabetically."""
    result = await stix_engine.search(
        stix_type="malware",
        query=q if q else None,
        from_=0,
        size=10000,
    )
    objects = result.get("objects", [])
    objects.sort(key=lambda x: (x.get("name") or "").lower())
    return {
        "total": len(objects),
        "offset": from_,
        "size": size,
        "objects": objects[from_:from_ + size],
    }


@router.get("/malware/{family_name}")
async def get_malware_profile(
    family_name: str = Path(..., min_length=1, max_length=255),
    user=Depends(get_current_user),
    stix_engine: STIXEngine = Depends(get_stix_engine),
):
    """Get full profile of a malware family: metadata + IOCs + actors + detection rules."""
    result = {
        "family": None,
        "iocs": [],
        "threat_actors": [],
        "sigma_rules": [],
        "yara_rules": [],
    }

    try:
        # Get malware object
        search_result = await stix_engine.search(
            stix_type="malware",
            query=family_name,
            size=1,
        )
        if search_result.get("objects"):
            result["family"] = search_result["objects"][0]

        # Get related IOCs (indicators with x_clawint_malware_families containing this family)
        ioc_result = await stix_engine.search(
            stix_type="indicator",
            query=family_name,
            size=50,
        )
        result["iocs"] = ioc_result.get("objects", [])[:20]

        # Get related threat actors (via STIX relationships)
        relationship_search = await stix_engine.search(
            stix_type="relationship",
            query=family_name,
            size=50,
        )
        actor_refs = set()
        for rel in relationship_search.get("objects", []):
            if rel.get("relationship_type") == "uses" and rel.get("target_ref", "").startswith("malware--"):
                actor_refs.add(rel.get("source_ref"))

        if actor_refs:
            for ref in list(actor_refs)[:10]:
                try:
                    actor_obj = await stix_engine.get_object(ref)
                    if actor_obj:
                        result["threat_actors"].append(actor_obj)
                except Exception:
                    pass

        # Get detection rules
        async with AsyncSessionLocal() as db:
            # Sigma rules
            sigma_stmt = select(DetectionRule).where(
                DetectionRule.rule_type == RuleType.sigma
            ).limit(100)
            sigma_result = await db.execute(sigma_stmt)
            sigma_rules = sigma_result.scalars().all()

            for rule in sigma_rules:
                rule_tags = {t.lower() for t in (rule.tags or [])}
                if family_name.lower() in rule_tags:
                    result["sigma_rules"].append({
                        "id": rule.id,
                        "name": rule.name,
                        "severity": rule.severity.value if rule.severity else "medium",
                    })

            # YARA rules
            yara_stmt = select(DetectionRule).where(
                DetectionRule.rule_type == RuleType.yara
            ).limit(100)
            yara_result = await db.execute(yara_stmt)
            yara_rules = yara_result.scalars().all()

            for rule in yara_rules:
                rule_tags = {t.lower() for t in (rule.tags or [])}
                if family_name.lower() in rule_tags:
                    result["yara_rules"].append({
                        "id": rule.id,
                        "name": rule.name,
                        "severity": rule.severity.value if rule.severity else "medium",
                    })

            result["sigma_rules"] = result["sigma_rules"][:20]
            result["yara_rules"] = result["yara_rules"][:20]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Profile lookup failed: {str(e)}",
        )

    return result
