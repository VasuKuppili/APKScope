import asyncio
import os
import logging
import requests
from typing import Dict, Any, Optional
from backend.threat_intelligence.cache_service import intel_cache

logger = logging.getLogger("virustotal_client")

VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files/"
VT_DOMAIN_ENDPOINT = "https://www.virustotal.com/api/v3/domains/"

class VirusTotalClient:
    """
    Client for VirusTotal API v3 lookups.
    Only active when VIRUSTOTAL_API_KEY is configured.
    Respects rate limits and terms. Strictly performs hash/indicator lookups;
    never uploads user APK files.
    """
    def __init__(self, api_key: Optional[str] = None, timeout: float = 3.5):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def _sync_lookup_hash(self, sha256: str) -> Dict[str, Any]:
        if not self.is_configured:
            return {
                "provider": "VirusTotal",
                "available": False,
                "matched": False,
                "status": "NOT_CONFIGURED",
                "message": "VirusTotal API key not configured"
            }

        cache_key = f"vt:hash:{sha256}"
        cached = intel_cache.get(cache_key)
        if cached is not None:
            cached_copy = dict(cached)
            cached_copy["cached"] = True
            return cached_copy

        headers = {
            "x-apikey": self.api_key.strip(),
            "User-Agent": "Android-Malware-Analyzer/2.0"
        }

        try:
            url = f"{VT_FILE_ENDPOINT}{sha256}"
            resp = requests.get(url, headers=headers, timeout=self.timeout)

            if resp.status_code == 404:
                res = {
                    "provider": "VirusTotal",
                    "available": True,
                    "matched": False,
                    "status": "NOT_FOUND",
                    "message": "Hash not observed in dataset",
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=43200)
                return res

            if resp.status_code == 429:
                return {
                    "provider": "VirusTotal",
                    "available": True,
                    "matched": False,
                    "status": "RATE_LIMIT",
                    "message": "API rate limit reached",
                    "cached": False
                }

            if resp.status_code != 200:
                return {
                    "provider": "VirusTotal",
                    "available": True,
                    "matched": False,
                    "status": "ERROR",
                    "message": f"HTTP {resp.status_code}",
                    "cached": False
                }

            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total_scanners = sum(stats.values()) if stats else 0

            # Consider matched if multiple reputable security vendors flag the hash
            is_matched = (malicious_count >= 3)
            res = {
                "provider": "VirusTotal",
                "available": True,
                "matched": is_matched,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "total_scanners": total_scanners,
                "popular_threat_category": attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "status": "MATCHED" if is_matched else "CLEAN",
                "cached": False
            }
            intel_cache.set(cache_key, res, ttl=86400)
            return res

        except requests.Timeout:
            return {
                "provider": "VirusTotal",
                "available": True,
                "matched": False,
                "status": "TIMEOUT",
                "cached": False
            }
        except Exception as e:
            return {
                "provider": "VirusTotal",
                "available": True,
                "matched": False,
                "status": "ERROR",
                "message": str(e),
                "cached": False
            }

    async def lookup_hash(self, sha256: str) -> Dict[str, Any]:
        if not sha256:
            return {"provider": "VirusTotal", "available": False, "matched": False, "status": "INVALID_INPUT"}
        return await asyncio.to_thread(self._sync_lookup_hash, sha256)
