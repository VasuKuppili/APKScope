from typing import Dict, Any, List

class EvidenceType:
    EXACT_HASH_MATCH = "EXACT_HASH_MATCH"
    RELATED_URL_MATCH = "RELATED_URL_MATCH"
    RELATED_DOMAIN_MATCH = "RELATED_DOMAIN_MATCH"
    RELATED_IP_MATCH = "RELATED_IP_MATCH"
    CERTIFICATE_MATCH = "CERTIFICATE_MATCH"
    MALWARE_FAMILY_ASSOCIATION = "MALWARE_FAMILY_ASSOCIATION"
    STATIC_SUSPICIOUS_INDICATOR = "STATIC_SUSPICIOUS_INDICATOR"
    RUNTIME_SUSPICIOUS_BEHAVIOR = "RUNTIME_SUSPICIOUS_BEHAVIOR"
    CONFIRMED_DATA_TRANSMISSION = "CONFIRMED_DATA_TRANSMISSION"

WEIGHTS = {
    EvidenceType.EXACT_HASH_MATCH: 1.00,
    EvidenceType.MALWARE_FAMILY_ASSOCIATION: 0.95,
    EvidenceType.CONFIRMED_DATA_TRANSMISSION: 0.85,
    EvidenceType.RELATED_URL_MATCH: 0.85,
    EvidenceType.CERTIFICATE_MATCH: 0.80,
    EvidenceType.RELATED_DOMAIN_MATCH: 0.75,
    EvidenceType.RELATED_IP_MATCH: 0.70,
    EvidenceType.RUNTIME_SUSPICIOUS_BEHAVIOR: 0.65,
    EvidenceType.STATIC_SUSPICIOUS_INDICATOR: 0.50,
}

SEVERITIES = {
    EvidenceType.EXACT_HASH_MATCH: "Critical",
    EvidenceType.MALWARE_FAMILY_ASSOCIATION: "High",
    EvidenceType.CONFIRMED_DATA_TRANSMISSION: "High",
    EvidenceType.RELATED_URL_MATCH: "High",
    EvidenceType.CERTIFICATE_MATCH: "High",
    EvidenceType.RELATED_DOMAIN_MATCH: "Medium",
    EvidenceType.RELATED_IP_MATCH: "Medium",
    EvidenceType.RUNTIME_SUSPICIOUS_BEHAVIOR: "Medium",
    EvidenceType.STATIC_SUSPICIOUS_INDICATOR: "Low",
}

class EvidenceScorer:
    """
    Evaluates and scores correlated evidence items across static, dynamic, ML,
    and threat intelligence sources according to match specificity and confidence.
    """

    @staticmethod
    def score_evidence_items(evidence_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not evidence_items:
            return {
                "composite_threat_score": 0.0,
                "threat_confidence": 0.0,
                "risk_tier": "Clean",
                "scored_items": []
            }

        scored_items = []
        total_weighted_score = 0.0
        max_possible_weight = 0.0

        for item in evidence_items:
            ev_type = item.get("type", EvidenceType.STATIC_SUSPICIOUS_INDICATOR)
            weight = WEIGHTS.get(ev_type, 0.5)
            severity = SEVERITIES.get(ev_type, "Low")
            
            # Base threat contribution
            base_score = item.get("base_score", 70.0 if weight >= 0.7 else 40.0)
            weighted_contrib = base_score * weight

            scored_item = {
                **item,
                "weight": weight,
                "severity": severity,
                "weighted_score": round(weighted_contrib, 2)
            }
            scored_items.append(scored_item)

            total_weighted_score += weighted_contrib
            max_possible_weight += (100.0 * weight)

        # Calculate composite score bounded to [0, 100]
        if max_possible_weight > 0:
            normalized = (total_weighted_score / max_possible_weight) * 100.0
            composite_score = min(100.0, max(0.0, round(normalized, 1)))
        else:
            composite_score = 0.0

        # High confidence if exact hash match or multiple indicators
        has_hash_match = any(it.get("type") == EvidenceType.EXACT_HASH_MATCH for it in evidence_items)
        has_url_or_domain = any(it.get("type") in [EvidenceType.RELATED_URL_MATCH, EvidenceType.RELATED_DOMAIN_MATCH] for it in evidence_items)

        if has_hash_match:
            confidence = 98.0
        elif has_url_or_domain and len(evidence_items) >= 2:
            confidence = 92.0
        elif len(evidence_items) >= 3:
            confidence = 88.0
        elif len(evidence_items) > 0:
            confidence = 75.0
        else:
            confidence = 0.0

        # Risk tier determination
        if composite_score >= 80 or has_hash_match:
            risk_tier = "Critical"
        elif composite_score >= 60:
            risk_tier = "High"
        elif composite_score >= 35:
            risk_tier = "Moderate"
        elif composite_score > 0:
            risk_tier = "Low"
        else:
            risk_tier = "Clean"

        return {
            "composite_threat_score": composite_score,
            "threat_confidence": confidence,
            "risk_tier": risk_tier,
            "scored_items": scored_items
        }
