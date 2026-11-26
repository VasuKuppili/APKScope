import asyncio
import logging
from typing import Dict, Any, List, Optional

from backend.threat_intelligence.indicator_extractor import IndicatorExtractor
from backend.threat_intelligence.indicator_normalizer import IndicatorNormalizer
from backend.threat_intelligence.malwarebazaar_client import MalwareBazaarClient
from backend.threat_intelligence.urlhaus_client import URLhausClient
from backend.threat_intelligence.threatfox_client import ThreatFoxClient
from backend.threat_intelligence.virustotal_client import VirusTotalClient
from backend.threat_intelligence.correlation_engine import CorrelationEngine

logger = logging.getLogger("threat_intelligence_service")

class ThreatIntelligenceService:
    """
    Modular threat intelligence service coordinating multi-source indicator extraction,
    asynchronous threat intelligence API querying, and unified evidence correlation.
    """

    def __init__(
        self,
        mb_client: Optional[MalwareBazaarClient] = None,
        uh_client: Optional[URLhausClient] = None,
        tf_client: Optional[ThreatFoxClient] = None,
        vt_client: Optional[VirusTotalClient] = None
    ):
        self.mb_client = mb_client or MalwareBazaarClient()
        self.uh_client = uh_client or URLhausClient()
        self.tf_client = tf_client or ThreatFoxClient()
        self.vt_client = vt_client or VirusTotalClient()

    async def enrich_indicators(
        self,
        file_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        static_data: Optional[Dict[str, Any]] = None,
        dynamic_data: Optional[Dict[str, Any]] = None,
        prediction: Optional[Dict[str, Any]] = None,
        timeout: float = 6.0
    ) -> Dict[str, Any]:
        """
        Runs the full threat intelligence enrichment pipeline.
        Gracefully degrades on timeouts or network failures.
        """
        try:
            # Step 1: Extract observables
            raw_indicators = IndicatorExtractor.extract_indicators(
                file_path=file_path,
                file_hash=file_hash,
                static_data=static_data,
                dynamic_data=dynamic_data
            )

            # Step 2: Normalize and filter
            norm = IndicatorNormalizer.normalize_indicators(raw_indicators)
            sha256 = norm["hashes"].get("sha256") or file_hash

            # Step 3: Dispatch concurrent API queries with total timeout guard
            tasks = []

            # Hash queries
            if sha256:
                tasks.append(self.mb_client.lookup_hash(sha256))
                if self.vt_client.is_configured:
                    tasks.append(self.vt_client.lookup_hash(sha256))

            # URL queries (limit to top 4 to respect rate limits and keep response snappy)
            for u in norm.get("urls", [])[:4]:
                tasks.append(self.uh_client.lookup_url(u))

            # Domain queries (limit to top 4)
            for d in norm.get("domains", [])[:4]:
                tasks.append(self.uh_client.lookup_host(d))
                tasks.append(self.tf_client.lookup_ioc(d))

            # IP queries (limit to top 3)
            for ip in norm.get("ips", [])[:3]:
                tasks.append(self.tf_client.lookup_ioc(ip))

            # Execute with overall timeout
            query_results = []
            if tasks:
                try:
                    done = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=timeout
                    )
                    for item in done:
                        if isinstance(item, dict):
                            query_results.append(item)
                        elif isinstance(item, Exception):
                            logger.warning(f"Threat intelligence query failed with exception: {item}")
                except asyncio.TimeoutError:
                    logger.warning("Threat intelligence overall query batch timed out.")
                except Exception as ex:
                    logger.warning(f"Error gathering threat intelligence tasks: {ex}")

            # Step 4: Evidence correlation and scoring
            correlation = CorrelationEngine.correlate(
                normalized_indicators=norm,
                ti_results=query_results,
                static_data=static_data,
                dynamic_data=dynamic_data,
                prediction=prediction
            )

            return correlation

        except Exception as e:
            logger.error(f"Threat intelligence enrichment pipeline failed: {e}", exc_info=True)
            # Return neutral fallback payload
            fallback_public = {
                "intelligence_match_status": "Threat Intelligence Enrichment Partially Unavailable",
                "hash_reputation": "Unobserved / Neutral",
                "domain_reputation": "Neutral / Unverified",
                "ip_reputation": "Neutral / Unverified",
                "malware_association": "None",
                "threat_confidence": 0.0,
                "composite_threat_score": 0.0,
                "risk_tier": "Clean",
                "correlated_evidence": [],
                "evidence_count": 0,
                "correlation_summary": (
                    "Threat intelligence enrichment could not be completed at this time. "
                    "Analysis proceeded with static and dynamic detection."
                ),
                "completed_at": None
            }
            return {
                "public": fallback_public,
                "audit": {"error": str(e)}
            }

# Global singleton service
ti_service = ThreatIntelligenceService()
