import hashlib
import os
import re
from typing import Dict, Any, List, Set, Optional

def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Computes SHA-256, SHA-1, and MD5 hashes of a file."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                sha1.update(chunk)
                md5.update(chunk)
        return {
            "sha256": sha256.hexdigest().lower(),
            "sha1": sha1.hexdigest().lower(),
            "md5": md5.hexdigest().lower()
        }
    return {
        "sha256": "",
        "sha1": "",
        "md5": ""
    }

class IndicatorExtractor:
    """
    Extracts all observable threat indicators (hashes, domains, IPs, URLs, certificates,
    and metadata) from static analysis features and dynamic runtime telemetry.
    """

    @staticmethod
    def extract_indicators(
        file_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        static_data: Optional[Dict[str, Any]] = None,
        dynamic_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        static = static_data or {}
        dynamic = dynamic_data or {}

        # 1. Hashes
        hashes = {"sha256": file_hash or "", "sha1": "", "md5": ""}
        if file_path and os.path.exists(file_path):
            computed = compute_file_hashes(file_path)
            if computed["sha256"]:
                hashes = computed
        elif not hashes["sha256"] and static.get("file_hash"):
            hashes["sha256"] = static["file_hash"]

        # 2. Package & Certificate Metadata
        package_name = static.get("package_name") or ""
        app_name = static.get("app_name") or ""
        version_name = static.get("version_name") or ""
        certificates = static.get("certificate_fingerprints") or []
        if isinstance(certificates, str):
            certificates = [certificates]

        # 3. URLs
        urls: Set[str] = set()
        for u in static.get("embedded_urls", []):
            if isinstance(u, str) and u.strip():
                urls.add(u.strip())

        # 4. Domains
        domains: Set[str] = set()
        for d in static.get("embedded_domains", []):
            if isinstance(d, str) and d.strip():
                domains.add(d.strip())

        # 5. IP Addresses
        ips: Set[str] = set()
        for ip in static.get("embedded_ips", []):
            if isinstance(ip, str) and ip.strip():
                ips.add(ip.strip())

        # 6. Dynamic Indicators
        dynamic_network = dynamic.get("network_indicators", [])
        if isinstance(dynamic_network, list):
            for net in dynamic_network:
                if isinstance(net, dict):
                    dest = net.get("destination", "")
                    ip_val = net.get("ip", "")
                    if dest and dest.startswith(("http://", "https://")):
                        urls.add(dest)
                    elif dest and "." in dest and not re.match(r"^\d+\.\d+\.\d+\.\d+$", dest):
                        domains.add(dest)
                    if ip_val:
                        ips.add(ip_val)

        # Dynamic redirect evidence
        redirect = dynamic.get("redirect_evidence")
        if isinstance(redirect, dict):
            r_url = redirect.get("redirect_url")
            r_dest = redirect.get("redirect_destination")
            if r_url:
                urls.add(r_url)
            if r_dest and "." in r_dest and not re.match(r"^\d+\.\d+\.\d+\.\d+$", r_dest):
                domains.add(r_dest)

        # Dynamic data leakage evidence
        leakage = dynamic.get("data_leakage_evidence")
        if isinstance(leakage, dict):
            dest_endpoint = leakage.get("destination_domain_or_ip")
            if dest_endpoint:
                if dest_endpoint.startswith(("http://", "https://")):
                    urls.add(dest_endpoint)
                elif re.match(r"^\d+\.\d+\.\d+\.\d+$", dest_endpoint):
                    ips.add(dest_endpoint)
                elif "." in dest_endpoint:
                    domains.add(dest_endpoint)

        return {
            "hashes": hashes,
            "package_name": package_name,
            "app_name": app_name,
            "version_name": version_name,
            "certificates": list(certificates),
            "urls": sorted(list(urls)),
            "domains": sorted(list(domains)),
            "ips": sorted(list(ips)),
            "permissions": static.get("permissions", []),
            "dangerous_permissions": static.get("dangerous_permissions", []),
            "sensitive_apis": static.get("sensitive_api_matches", [])
        }
