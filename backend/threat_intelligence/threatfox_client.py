import asyncio
import os
import logging
import requests
from typing import Dict, Any, Optional
from backend.threat_intelligence.cache_service import intel_cache

logger = logging.getLogger("threatfox_client")

API_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

class ThreatFoxClient:
    """
    Client for ThreatFox (abuse.ch) IOC Search API.
    Identifies known command-and-control (C2) servers, botnet infrastructure,
    malicious IP addresses, and malicious domains.
    """
    def __init__(self, api_key: Optional[str] = None, timeout: float = 3.5):
        self.api_key = api_key or os.getenv("THREATFOX_API_KEY", "")
        self.timeout = timeout

    def _sync_lookup_ioc(self, search_term: str) -> Dict[str, Any]:
        cache_key = f"threatfox:ioc:{search_term}"
        cached = intel_cache.get(cache_key)
        if cached is not None:
            cached_copy = dict(cached)
            cached_copy["cached"] = True
            return cached_copy

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Android-Malware-Analyzer/2.0"
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key
            headers["API-KEY"] = self.api_key

        payload = {
            "query": "search_ioc",
            "search_term": search_term
        }

        try:
            resp = requests.post(API_ENDPOINT, json=payload, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                return {
                    "provider": "ThreatFox",
                    "indicator_value": search_term,
                    "matched": False,
                    "status": "RATE_LIMIT"
                }
            if resp.status_code != 200:
                return {
                    "provider": "ThreatFox",
                    "indicator_value": search_term,
                    "matched": False,
                    "status": "ERROR",
                    "message": f"HTTP {resp.status_code}"
                }

            data = resp.json()
            query_status = data.get("query_status", "")

            if query_status == "ok":
                items = data.get("data", [])
                first_item = items[0] if items else {}
                res = {
                    "provider": "ThreatFox",
                    "indicator_value": search_term,
                    "matched": True,
                    "threat_type": first_item.get("threat_type"),
                    "threat_type_desc": first_item.get("threat_type_desc"),
                    "ioc_type": first_item.get("ioc_type"),
                    "malware_printable": first_item.get("malware_printable"),
                    "confidence_level": first_item.get("confidence_level", 75),
                    "tags": first_item.get("tags") or [],
                    "first_seen": first_item.get("first_seen"),
                    "status": "MATCHED",
                    "raw_status": query_status,
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=86400)
                return res
            else:
                res = {
                    "provider": "ThreatFox",
                    "indicator_value": search_term,
                    "matched": False,
                    "status": "CLEAN",
                    "raw_status": query_status,
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=43200)
                return res

        except requests.Timeout:
            return {
                "provider": "ThreatFox",
                "indicator_value": search_term,
                "matched": False,
                "status": "TIMEOUT"
            }
        except Exception as e:
            return {
                "provider": "ThreatFox",
                "indicator_value": search_term,
                "matched": False,
                "status": "ERROR",
                "message": str(e)
            }

    async def lookup_ioc(self, search_term: str) -> Dict[str, Any]:
        if not search_term:
            return {"provider": "ThreatFox", "matched": False, "status": "INVALID_INPUT"}
        return await asyncio.to_thread(self._sync_lookup_ioc, search_term)
