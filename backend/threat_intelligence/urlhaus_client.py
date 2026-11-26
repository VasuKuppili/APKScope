import asyncio
import os
import logging
import requests
from typing import Dict, Any, Optional
from backend.threat_intelligence.cache_service import intel_cache

logger = logging.getLogger("urlhaus_client")

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

class URLhausClient:
    """
    Client for URLhaus (abuse.ch) URL and Host threat intelligence lookup APIs.
    Identifies malware distribution sites and malicious URLs.
    """
    def __init__(self, api_key: Optional[str] = None, timeout: float = 3.5):
        self.api_key = api_key or os.getenv("URLHAUS_API_KEY", "")
        self.timeout = timeout

    def _sync_lookup_url(self, url: str) -> Dict[str, Any]:
        cache_key = f"urlhaus:url:{url}"
        cached = intel_cache.get(cache_key)
        if cached is not None:
            cached_copy = dict(cached)
            cached_copy["cached"] = True
            return cached_copy

        headers = {"User-Agent": "Android-Malware-Analyzer/2.0"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
            headers["API-KEY"] = self.api_key

        try:
            resp = requests.post(URL_ENDPOINT, data={"url": url}, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                return {
                    "provider": "URLhaus",
                    "indicator_type": "url",
                    "indicator_value": url,
                    "matched": False,
                    "status": "RATE_LIMIT"
                }
            if resp.status_code != 200:
                return {
                    "provider": "URLhaus",
                    "indicator_type": "url",
                    "indicator_value": url,
                    "matched": False,
                    "status": "ERROR",
                    "message": f"HTTP {resp.status_code}"
                }

            data = resp.json()
            query_status = data.get("query_status", "")

            if query_status == "ok":
                res = {
                    "provider": "URLhaus",
                    "indicator_type": "url",
                    "indicator_value": url,
                    "matched": True,
                    "threat": data.get("threat") or "malware_download",
                    "url_status": data.get("url_status"),
                    "tags": data.get("tags") or [],
                    "status": "MATCHED",
                    "raw_status": query_status,
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=86400)
                return res
            else:
                res = {
                    "provider": "URLhaus",
                    "indicator_type": "url",
                    "indicator_value": url,
                    "matched": False,
                    "status": "CLEAN",
                    "raw_status": query_status,
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=43200)
                return res

        except requests.Timeout:
            return {
                "provider": "URLhaus",
                "indicator_type": "url",
                "indicator_value": url,
                "matched": False,
                "status": "TIMEOUT"
            }
        except Exception as e:
            return {
                "provider": "URLhaus",
                "indicator_type": "url",
                "indicator_value": url,
                "matched": False,
                "status": "ERROR",
                "message": str(e)
            }

    def _sync_lookup_host(self, host: str) -> Dict[str, Any]:
        cache_key = f"urlhaus:host:{host}"
        cached = intel_cache.get(cache_key)
        if cached is not None:
            cached_copy = dict(cached)
            cached_copy["cached"] = True
            return cached_copy

        headers = {"User-Agent": "Android-Malware-Analyzer/2.0"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
            headers["API-KEY"] = self.api_key

        try:
            resp = requests.post(HOST_ENDPOINT, data={"host": host}, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                return {
                    "provider": "URLhaus",
                    "indicator_type": "host",
                    "indicator_value": host,
                    "matched": False,
                    "status": "RATE_LIMIT"
                }
            if resp.status_code != 200:
                return {
                    "provider": "URLhaus",
                    "indicator_type": "host",
                    "indicator_value": host,
                    "matched": False,
                    "status": "ERROR"
                }

            data = resp.json()
            query_status = data.get("query_status", "")

            if query_status == "ok":
                urls_count = len(data.get("urls", []))
                res = {
                    "provider": "URLhaus",
                    "indicator_type": "host",
                    "indicator_value": host,
                    "matched": True,
                    "malicious_urls_count": urls_count,
                    "threat": data.get("threat") or "malware_host",
                    "firstseen": data.get("firstseen"),
                    "status": "MATCHED",
                    "raw_status": query_status,
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=86400)
                return res
            else:
                res = {
                    "provider": "URLhaus",
                    "indicator_type": "host",
                    "indicator_value": host,
                    "matched": False,
                    "status": "CLEAN",
                    "raw_status": query_status,
                    "cached": False
                }
                intel_cache.set(cache_key, res, ttl=43200)
                return res

        except requests.Timeout:
            return {
                "provider": "URLhaus",
                "indicator_type": "host",
                "indicator_value": host,
                "matched": False,
                "status": "TIMEOUT"
            }
        except Exception as e:
            return {
                "provider": "URLhaus",
                "indicator_type": "host",
                "indicator_value": host,
                "matched": False,
                "status": "ERROR",
                "message": str(e)
            }

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        if not url:
            return {"provider": "URLhaus", "matched": False, "status": "INVALID_INPUT"}
        return await asyncio.to_thread(self._sync_lookup_url, url)

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        if not host:
            return {"provider": "URLhaus", "matched": False, "status": "INVALID_INPUT"}
        return await asyncio.to_thread(self._sync_lookup_host, host)
