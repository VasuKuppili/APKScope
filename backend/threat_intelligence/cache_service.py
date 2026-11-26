import time
import json
import os
import threading
import logging
from typing import Optional, Any, Dict

logger = logging.getLogger("threat_intel_cache")

class ThreatIntelCache:
    """
    Thread-safe in-memory and persistent TTL cache for external threat-intelligence lookups.
    Avoids repeat API queries, prevents rate limits, and speeds up analysis.
    """
    def __init__(self, cache_file: Optional[str] = None, default_ttl: int = 86400):
        self._lock = threading.Lock()
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        
        if cache_file is None:
            cache_dir = os.path.dirname(os.path.abspath(__file__))
            self.cache_file = os.path.join(cache_dir, ".threat_intel_cache.json")
        else:
            self.cache_file = cache_file

        self._load_from_disk()

    def _load_from_disk(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    now = time.time()
                    # Filter out expired items on load
                    valid_items = {k: v for k, v in data.items() if v.get("expires_at", 0) > now}
                    self._memory_cache.update(valid_items)
        except Exception as e:
            logger.warning(f"Could not load persistent threat intel cache: {e}")

    def _save_to_disk(self):
        try:
            now = time.time()
            valid_items = {k: v for k, v in self._memory_cache.items() if v.get("expires_at", 0) > now}
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(valid_items, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save threat intel cache to disk: {e}")

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._memory_cache.get(key)
            if not entry:
                return None
            
            if time.time() > entry.get("expires_at", 0):
                # Expired
                self._memory_cache.pop(key, None)
                return None
            
            return entry.get("payload")

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            effective_ttl = ttl if ttl is not None else self.default_ttl
            expires_at = time.time() + effective_ttl
            self._memory_cache[key] = {
                "expires_at": expires_at,
                "created_at": time.time(),
                "payload": value
            }
            # Periodically or on update persist
            if len(self._memory_cache) % 5 == 0:
                self._save_to_disk()

    def clear(self) -> None:
        with self._lock:
            self._memory_cache.clear()
            if os.path.exists(self.cache_file):
                try:
                    os.remove(self.cache_file)
                except Exception:
                    pass

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            active_count = sum(1 for v in self._memory_cache.values() if v.get("expires_at", 0) > now)
            return {
                "total_cached_entries": len(self._memory_cache),
                "active_valid_entries": active_count,
                "cache_file": self.cache_file
            }

# Global singleton cache instance
intel_cache = ThreatIntelCache()
