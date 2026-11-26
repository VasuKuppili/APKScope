import json
from datetime import datetime, timezone
from stix2 import Identity, Indicator, Malware, Relationship, Bundle

def generate_stix_bundle(analysis_record: dict) -> dict:
    file_hash = analysis_record.get("file_hash", "0" * 64)
    filename = analysis_record.get("filename", "unknown.apk")
    classification = analysis_record.get("classification", "Unknown")
    family = analysis_record.get("malware_family") or "Android.Malware.Generic"
    confidence = analysis_record.get("confidence_score") or 0.0

    # STIX Identity SDO representing authoring platform
    author_identity = Identity(
        name="Android Malware Classification & Threat Intelligence Platform",
        identity_class="organization",
        description="Automated static and dynamic Android malware family classification engine with Explainable AI."
    )

    # STIX Indicator with standard Cyber Observable Pattern
    indicator = Indicator(
        name=f"Android Malware Indicator - {filename}",
        description=f"File hash identified during automated analysis with {confidence}% confidence.",
        pattern=f"[file:hashes.'SHA-256' = '{file_hash}']",
        pattern_type="stix",
        created_by_ref=author_identity.id,
        valid_from=datetime.now(timezone.utc)
    )

    class_upper = str(classification).upper()
    is_mal = "MALICIOUS" in class_upper or "PHISHING" in class_upper or "DATA LEAKAGE" in class_upper or "PRIVACY" in class_upper

    if "PHISHING" in class_upper:
        malware_name = "Phishing.DeceptiveRedirect"
    elif "DATA LEAKAGE" in class_upper or "PRIVACY" in class_upper:
        malware_name = "PrivacyRisk.UnauthorizedTelemetry"
    elif is_mal and family and family != "Benign":
        malware_name = family
    else:
        malware_name = "Benign.Application"

    malware = Malware(
        name=malware_name,
        is_family=is_mal,
        created_by_ref=author_identity.id,
        description=f"Automated threat analysis for {filename}. Classification: {classification}. Confidence: {confidence}%."
    )

    relationship = Relationship(
        source_ref=indicator.id,
        relationship_type="indicates",
        target_ref=malware.id,
        created_by_ref=author_identity.id,
        description=f"Observed SHA-256 pattern indicates membership in family {family}."
    )

    objects = [author_identity, indicator, malware, relationship]

    # Optionally enrich STIX bundle with correlated threat intelligence observables
    ti = analysis_record.get("threat_intelligence")
    if isinstance(ti, dict) and is_mal:
        correlated = ti.get("correlated_evidence", [])
        for item in correlated:
            obs = item.get("observable")
            category = item.get("category", "")
            if obs and category in ["Domain Reputation", "Known Threat Indicator", "IP Reputation"]:
                try:
                    if category == "Domain Reputation":
                        pattern = f"[domain-name:value = '{obs}']"
                    elif category == "IP Reputation":
                        pattern = f"[ipv4-addr:value = '{obs}']"
                    else:
                        pattern = f"[url:value = '{obs}']"

                    extra_ind = Indicator(
                        name=f"Correlated Indicator - {obs}",
                        description=f"Correlated threat observable: {item.get('assessment', '')}",
                        pattern=pattern,
                        pattern_type="stix",
                        created_by_ref=author_identity.id,
                        valid_from=datetime.now(timezone.utc)
                    )
                    rel = Relationship(
                        source_ref=extra_ind.id,
                        relationship_type="indicates",
                        target_ref=malware.id,
                        created_by_ref=author_identity.id
                    )
                    objects.extend([extra_ind, rel])
                except Exception:
                    pass

    bundle = Bundle(objects=objects)
    return json.loads(bundle.serialize())
