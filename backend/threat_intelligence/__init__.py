"""
Threat Intelligence package for Android Malware Family Classification Platform.
Provides indicator extraction, normalization, external API lookups (MalwareBazaar,
URLhaus, ThreatFox, VirusTotal), and evidence correlation.
"""

from backend.threat_intelligence.cache_service import intel_cache, ThreatIntelCache
from backend.threat_intelligence.indicator_extractor import IndicatorExtractor
from backend.threat_intelligence.indicator_normalizer import IndicatorNormalizer
from backend.threat_intelligence.evidence_scorer import EvidenceScorer, EvidenceType
from backend.threat_intelligence.correlation_engine import CorrelationEngine
from backend.threat_intelligence.threat_intelligence_service import ThreatIntelligenceService, ti_service
from backend.threat_intelligence.stix_generator import generate_stix_bundle

__all__ = [
    "intel_cache",
    "ThreatIntelCache",
    "IndicatorExtractor",
    "IndicatorNormalizer",
    "EvidenceScorer",
    "EvidenceType",
    "CorrelationEngine",
    "ThreatIntelligenceService",
    "ti_service",
    "generate_stix_bundle"
]
