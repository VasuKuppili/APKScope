import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from backend.threat_intelligence.evidence_scorer import EvidenceScorer, EvidenceType

# Providers to sanitize from user-facing text
RESTRICTED_TERMS = [
    r"malwarebazaar",
    r"urlhaus",
    r"threatfox",
    r"virustotal",
    r"abuse\.ch",
    r"https?://[^\s]+"
]

def sanitize_user_facing_text(text: str) -> str:
    """Removes any external threat provider names, URLs, or API references from user-facing text."""
    if not text or not isinstance(text, str):
        return ""
    sanitized = text
    # Replace provider names with generic security terms
    sanitized = re.sub(r"malwarebazaar", "Threat Intelligence Signature Database", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"urlhaus", "Threat Intelligence URL Repository", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"threatfox", "Global IOC Infrastructure Database", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"virustotal", "Multi-Scanner Threat Intelligence Engine", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"abuse\.ch", "Global Threat Repository", sanitized, flags=re.IGNORECASE)
    # Remove raw URLs in messages
    sanitized = re.sub(r"https?://[a-zA-Z0-9.-]+(?:/[^\s]*)?", "[Threat Endpoint]", sanitized)
    return sanitized

class CorrelationEngine:
    """
    Evidence Correlation Engine that correlates static APK features, dynamic runtime telemetry,
    ML classification verdicts, and external threat-intelligence lookups.
    
    Generates a clean, professional user-facing security assessment with zero third-party provider
    branding or query URLs, while retaining detailed provenance internally for audit logs.
    """

    @staticmethod
    def correlate(
        normalized_indicators: Dict[str, Any],
        ti_results: List[Dict[str, Any]],
        static_data: Optional[Dict[str, Any]] = None,
        dynamic_data: Optional[Dict[str, Any]] = None,
        prediction: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        static = static_data or {}
        dynamic = dynamic_data or {}
        pred = prediction or {}

        evidence_items: List[Dict[str, Any]] = []
        audit_events: List[Dict[str, Any]] = []

        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Process External Threat Intelligence Results
        exact_hash_matched = False
        ti_malware_family = None
        has_domain_match = False
        has_url_match = False
        has_ip_match = False

        any_ti_available = False
        any_ti_matched = False

        for res in ti_results:
            provider = res.get("provider", "ThreatIntelProvider")
            status = res.get("status", "")
            matched = res.get("matched", False)
            cached = res.get("cached", False)

            if status not in ["TIMEOUT", "ERROR", "NOT_CONFIGURED", "RATE_LIMIT"]:
                any_ti_available = True

            # Record internal audit provenance
            audit_events.append({
                "provider": provider,
                "indicator_type": res.get("indicator_type"),
                "indicator_value": res.get("indicator_value"),
                "status": status,
                "matched": matched,
                "cached": cached,
                "timestamp": now_iso,
                "raw_details": {k: v for k, v in res.items() if k not in ["provider", "indicator_type", "indicator_value", "cached"]}
            })

            if matched:
                any_ti_matched = True
                ind_type = res.get("indicator_type")
                ind_val = str(res.get("indicator_value", ""))

                if ind_type == "sha256":
                    exact_hash_matched = True
                    family = res.get("malware_family") or res.get("popular_threat_category") or "Malicious.Artifact"
                    ti_malware_family = family
                    evidence_items.append({
                        "type": EvidenceType.EXACT_HASH_MATCH,
                        "category": "Hash Reputation",
                        "observable": f"{ind_val[:16]}..." if len(ind_val) > 16 else ind_val,
                        "assessment": f"Exact file hash matches known malicious signature ({family})",
                        "base_score": 95.0
                    })
                    evidence_items.append({
                        "type": EvidenceType.MALWARE_FAMILY_ASSOCIATION,
                        "category": "Malware Association",
                        "observable": family,
                        "assessment": f"Identified association with malware family: {family}",
                        "base_score": 90.0
                    })

                elif ind_type == "url":
                    has_url_match = True
                    threat = res.get("threat") or "Malicious URL"
                    evidence_items.append({
                        "type": EvidenceType.RELATED_URL_MATCH,
                        "category": "Known Threat Indicator",
                        "observable": ind_val,
                        "assessment": f"Embedded destination matches confirmed malicious delivery URL ({threat})",
                        "base_score": 85.0
                    })

                elif ind_type in ["host", "domain"]:
                    has_domain_match = True
                    evidence_items.append({
                        "type": EvidenceType.RELATED_DOMAIN_MATCH,
                        "category": "Domain Reputation",
                        "observable": ind_val,
                        "assessment": "Associated host domain identified as malicious distribution infrastructure",
                        "base_score": 80.0
                    })

                elif ind_type in ["ip", "ip:port"]:
                    has_ip_match = True
                    threat_desc = res.get("threat_type_desc") or "Command and Control host"
                    evidence_items.append({
                        "type": EvidenceType.RELATED_IP_MATCH,
                        "category": "IP Reputation",
                        "observable": ind_val,
                        "assessment": f"Target IP matches known malicious infrastructure ({threat_desc})",
                        "base_score": 75.0
                    })

        # 2. Correlate Dynamic Runtime Telemetry (if available)
        if dynamic:
            redirect = dynamic.get("redirect_evidence")
            if redirect and isinstance(redirect, dict):
                evidence_items.append({
                    "type": EvidenceType.RUNTIME_SUSPICIOUS_BEHAVIOR,
                    "category": "Runtime Behavior",
                    "observable": redirect.get("redirect_destination", "Deceptive Browser Redirect"),
                    "assessment": "Automated runtime execution detected unauthorized deceptive URL redirection",
                    "base_score": 75.0
                })

            leakage = dynamic.get("data_leakage_evidence")
            if leakage and isinstance(leakage, dict):
                evidence_items.append({
                    "type": EvidenceType.CONFIRMED_DATA_TRANSMISSION,
                    "category": "Telemetry & Privacy",
                    "observable": leakage.get("destination_domain_or_ip", "Telemetry Endpoint"),
                    "assessment": "Observed unauthorized transmission of sensitive device identifiers over network",
                    "base_score": 85.0
                })

            mal_ev = dynamic.get("malicious_evidence")
            if mal_ev and isinstance(mal_ev, dict):
                evidence_items.append({
                    "type": EvidenceType.RUNTIME_SUSPICIOUS_BEHAVIOR,
                    "category": "Runtime Behavior",
                    "observable": mal_ev.get("predicted_malware_family", "Dropper Payload"),
                    "assessment": mal_ev.get("observed_behavior", "Malicious payload installation detected"),
                    "base_score": 85.0
                })

        # 3. Correlate Static Heuristic & Attack Surface Indicators
        heuristic_list = pred.get("heuristic_indicators") or []
        for heur in heuristic_list:
            evidence_items.append({
                "type": EvidenceType.STATIC_SUSPICIOUS_INDICATOR,
                "category": "Static Threat Indicator",
                "observable": heur,
                "assessment": f"Static heuristic rule triggered: {heur}",
                "base_score": 60.0
            })

        # 4. Score Correlated Evidence
        scoring = EvidenceScorer.score_evidence_items(evidence_items)

        # 5. Formulate Clean User-Facing Reputations
        if exact_hash_matched:
            hash_rep = "Flagged Malicious Signature"
        elif any_ti_available:
            hash_rep = "Clean / No Malicious Records"
        else:
            hash_rep = "Unobserved / Neutral"

        if has_domain_match or has_url_match:
            domain_rep = "Suspicious / Known Threat Infrastructure"
        elif normalized_indicators.get("domains"):
            domain_rep = "Reputable / No Threat Association"
        else:
            domain_rep = "Internal / No External Domains"

        if has_ip_match:
            ip_rep = "Suspicious / Known C2 Host"
        elif normalized_indicators.get("ips"):
            ip_rep = "Reputable / No Suspicious Association"
        else:
            ip_rep = "Internal / No Public IPs"

        malware_assoc = ti_malware_family or pred.get("malware_family") or "None"
        if malware_assoc in ["Benign", "Clean", "Unknown"]:
            malware_assoc = "None"

        # Intelligence Match Status
        if any_ti_matched:
            match_status = "Confirmed Threat Indicators Correlated"
        elif any_ti_available:
            match_status = "No Known Threat Indicators Identified"
        else:
            match_status = "Threat Intelligence Enrichment Partially Unavailable"

        # Generate professional correlation summary
        if any_ti_matched:
            summary = (
                f"Threat intelligence correlation confirmed malicious threat indicators. "
                f"Hash reputation status: {hash_rep}. Domain reputation: {domain_rep}. "
                f"Correlated malware family association: {malware_assoc}."
            )
        elif not any_ti_available:
            summary = (
                "External threat intelligence lookups were partially unavailable or timed out. "
                "Analysis proceeded autonomously relying on local static signature extraction, "
                "isolated dynamic execution telemetry, and Explainable AI evaluation."
            )
        else:
            summary = (
                "Threat intelligence correlation completed across all query observables. "
                "No known malicious hashes, suspicious distribution endpoints, or command-and-control "
                "infrastructure matches were identified for this application."
            )

        # Sanitize any accidental provider names from public evidence items
        clean_evidence_items = []
        for item in scoring["scored_items"]:
            clean_item = {
                "type": item["type"],
                "category": sanitize_user_facing_text(item.get("category", "")),
                "observable": sanitize_user_facing_text(str(item.get("observable", ""))),
                "assessment": sanitize_user_facing_text(item.get("assessment", "")),
                "severity": item.get("severity", "Low"),
                "weight": item.get("weight", 0.5)
            }
            clean_evidence_items.append(clean_item)

        # Public User-Facing Payload
        public_payload = {
            "intelligence_match_status": match_status,
            "hash_reputation": hash_rep,
            "domain_reputation": domain_rep,
            "ip_reputation": ip_rep,
            "malware_association": malware_assoc,
            "threat_confidence": scoring["threat_confidence"],
            "composite_threat_score": scoring["composite_threat_score"],
            "risk_tier": scoring["risk_tier"],
            "correlated_evidence": clean_evidence_items,
            "evidence_count": len(clean_evidence_items),
            "correlation_summary": sanitize_user_facing_text(summary),
            "completed_at": now_iso
        }

        # Internal Audit Payload (for audit verification)
        audit_payload = {
            "sha256": normalized_indicators.get("hashes", {}).get("sha256"),
            "audit_events": audit_events,
            "indicators_queried": {
                "domains_count": len(normalized_indicators.get("domains", [])),
                "ips_count": len(normalized_indicators.get("ips", [])),
                "urls_count": len(normalized_indicators.get("urls", []))
            },
            "timestamp": now_iso
        }

        return {
            "public": public_payload,
            "audit": audit_payload
        }
