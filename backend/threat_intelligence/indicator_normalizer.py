import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List, Set

# Generic schema namespaces and non-external domains that should never be queried to external TI APIs
BENIGN_NAMESPACE_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "apache.org",
    "xml.org",
    "schema.org",
    "xmlns.com",
    "localhost",
    "example.com",
    "example.org",
    "example.net",
    "android.com",
    "openmobilealliance.org"
}

def is_valid_sha256(h: str) -> bool:
    if not isinstance(h, str):
        return False
    return bool(re.match(r"^[a-fA-F0-9]{64}$", h.strip()))

def is_valid_sha1(h: str) -> bool:
    if not isinstance(h, str):
        return False
    return bool(re.match(r"^[a-fA-F0-9]{40}$", h.strip()))

def is_valid_md5(h: str) -> bool:
    if not isinstance(h, str):
        return False
    return bool(re.match(r"^[a-fA-F0-9]{32}$", h.strip()))

def is_routable_public_ip(ip_str: str) -> bool:
    """Checks if an IP address is valid and publicly routable (not private, loopback, or multicast)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (
            ip.is_private or
            ip.is_loopback or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_link_local or
            ip.is_unspecified
        )
    except ValueError:
        return False

def normalize_domain(domain: str) -> str:
    """Strips protocol, paths, ports, and whitespace from a domain string."""
    if not domain or not isinstance(domain, str):
        return ""
    d = domain.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        try:
            parsed = urlparse(d)
            d = parsed.netloc or parsed.path
        except Exception:
            pass
    # Strip port if present
    if ":" in d:
        d = d.split(":")[0]
    # Strip trailing slashes or paths
    d = d.split("/")[0].strip()
    return d

def is_valid_domain(domain: str) -> bool:
    """Validates if string is a valid Internet domain (not an IP and has valid TLD)."""
    d = normalize_domain(domain)
    if not d or len(d) > 253 or d in BENIGN_NAMESPACE_DOMAINS:
        return False
    # Check if it's an IP
    try:
        ipaddress.ip_address(d)
        return False
    except ValueError:
        pass
    # Domain regex: supports 2-level (e.g. example.com) and multi-level (sub.example.com)
    pattern = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$"
    return bool(re.match(pattern, d))

def normalize_url(url: str) -> str:
    """Normalizes URL string, ensuring valid scheme and rejecting standard XML namespaces."""
    if not url or not isinstance(url, str):
        return ""
    u = url.strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return ""
    try:
        parsed = urlparse(u)
        hostname = (parsed.hostname or "").lower()
        if hostname in BENIGN_NAMESPACE_DOMAINS or not parsed.netloc:
            return ""
        # Reconstruct clean URL
        return u
    except Exception:
        return ""

class IndicatorNormalizer:
    """
    Cleans, normalizes, and filters extracted indicators to prepare them for
    accurate threat intelligence correlation without false positives from local/schema namespaces.
    """

    @staticmethod
    def normalize_indicators(raw_indicators: Dict[str, Any]) -> Dict[str, Any]:
        hashes = raw_indicators.get("hashes", {})
        sha256 = hashes.get("sha256", "").strip().lower()
        sha1 = hashes.get("sha1", "").strip().lower()
        md5 = hashes.get("md5", "").strip().lower()

        valid_hashes = {
            "sha256": sha256 if is_valid_sha256(sha256) else "",
            "sha1": sha1 if is_valid_sha1(sha1) else "",
            "md5": md5 if is_valid_md5(md5) else ""
        }

        # Normalize domains
        normalized_domains: Set[str] = set()
        for d in raw_indicators.get("domains", []):
            norm_d = normalize_domain(d)
            if is_valid_domain(norm_d):
                normalized_domains.add(norm_d)

        # Normalize IPs
        normalized_ips: Set[str] = set()
        for ip in raw_indicators.get("ips", []):
            clean_ip = ip.strip()
            # If IP has port, separate it
            if ":" in clean_ip and not clean_ip.startswith("["):
                clean_ip = clean_ip.split(":")[0]
            if is_routable_public_ip(clean_ip):
                normalized_ips.add(clean_ip)

        # Normalize URLs
        normalized_urls: Set[str] = set()
        for u in raw_indicators.get("urls", []):
            norm_u = normalize_url(u)
            if norm_u:
                normalized_urls.add(norm_u)

        return {
            "hashes": valid_hashes,
            "package_name": raw_indicators.get("package_name", "").strip(),
            "app_name": raw_indicators.get("app_name", "").strip(),
            "version_name": raw_indicators.get("version_name", "").strip(),
            "certificates": raw_indicators.get("certificates", []),
            "domains": sorted(list(normalized_domains)),
            "ips": sorted(list(normalized_ips)),
            "urls": sorted(list(normalized_urls)),
            "permissions": raw_indicators.get("permissions", []),
            "dangerous_permissions": raw_indicators.get("dangerous_permissions", []),
            "sensitive_apis": raw_indicators.get("sensitive_apis", [])
        }
