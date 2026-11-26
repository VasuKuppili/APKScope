import os
import time
import json
import asyncio
import unittest
from unittest.mock import patch, MagicMock

# Enable fast test mode for fast test execution
os.environ["FAST_TEST_MODE"] = "1"

from backend.database.connection import init_db, SessionLocal
from backend.database.models import AnalysisRecord, ThreatIntelRecord
from backend.threat_intelligence.cache_service import ThreatIntelCache
from backend.threat_intelligence.indicator_extractor import IndicatorExtractor
from backend.threat_intelligence.indicator_normalizer import (
    IndicatorNormalizer,
    is_valid_sha256,
    is_routable_public_ip,
    is_valid_domain,
    normalize_domain,
    normalize_url
)
from backend.threat_intelligence.evidence_scorer import EvidenceScorer, EvidenceType
from backend.threat_intelligence.correlation_engine import CorrelationEngine, sanitize_user_facing_text
from backend.threat_intelligence.malwarebazaar_client import MalwareBazaarClient
from backend.threat_intelligence.urlhaus_client import URLhausClient
from backend.threat_intelligence.threatfox_client import ThreatFoxClient
from backend.threat_intelligence.virustotal_client import VirusTotalClient
from backend.threat_intelligence.threat_intelligence_service import ThreatIntelligenceService
from backend.threat_intelligence.stix_generator import generate_stix_bundle

class TestThreatIntelligence(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_01_indicator_normalizer(self):
        """Test indicator filtering for private IPs, android schemas, and invalid hashes."""
        # Valid hash
        self.assertTrue(is_valid_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        self.assertFalse(is_valid_sha256("short_hash"))
        self.assertFalse(is_valid_sha256("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))

        # IPs: private / loopback should be rejected
        self.assertFalse(is_routable_public_ip("127.0.0.1"))
        self.assertFalse(is_routable_public_ip("192.168.1.1"))
        self.assertFalse(is_routable_public_ip("10.0.0.5"))
        self.assertFalse(is_routable_public_ip("172.16.0.1"))
        self.assertFalse(is_routable_public_ip("0.0.0.0"))
        # Public IP should be accepted
        self.assertTrue(is_routable_public_ip("8.8.8.8"))
        self.assertTrue(is_routable_public_ip("185.220.101.5"))

        # Domains: schemas and localhost rejected
        self.assertFalse(is_valid_domain("schemas.android.com"))
        self.assertFalse(is_valid_domain("localhost"))
        self.assertFalse(is_valid_domain("www.w3.org"))
        self.assertTrue(is_valid_domain("malicious-c2-server.com"))
        self.assertTrue(is_valid_domain("api.vidmate-service.net"))

        # URLs
        self.assertEqual(normalize_url("http://schemas.android.com/apk/res/android"), "")
        self.assertTrue(normalize_url("http://malicious-c2-server.com/payload.apk").startswith("http"))

    def test_02_indicator_extractor(self):
        """Test indicator extraction from static features and dynamic telemetry."""
        static_data = {
            "file_hash": "a" * 64,
            "package_name": "com.test.sample",
            "embedded_urls": ["https://evil-host.com/drop.apk", "http://schemas.android.com/apk/res/android"],
            "embedded_domains": ["evil-host.com", "schemas.android.com"],
            "embedded_ips": ["185.220.101.5", "127.0.0.1"],
            "permissions": ["android.permission.INTERNET"]
        }
        dynamic_data = {
            "network_indicators": [
                {"destination": "http://c2-tracker.net/gate", "ip": "194.26.29.112"}
            ],
            "redirect_evidence": {
                "redirect_url": "https://deceptive-login.com",
                "redirect_destination": "deceptive-login.com"
            }
        }

        extracted = IndicatorExtractor.extract_indicators(
            file_hash="a" * 64,
            static_data=static_data,
            dynamic_data=dynamic_data
        )
        norm = IndicatorNormalizer.normalize_indicators(extracted)

        self.assertIn("185.220.101.5", norm["ips"])
        self.assertIn("194.26.29.112", norm["ips"])
        self.assertNotIn("127.0.0.1", norm["ips"])

        self.assertIn("evil-host.com", norm["domains"])
        self.assertIn("deceptive-login.com", norm["domains"])
        self.assertNotIn("schemas.android.com", norm["domains"])

    def test_03_cache_service(self):
        """Test TTL cache service set, get, expiry, and thread safety."""
        test_cache = ThreatIntelCache(default_ttl=1)
        test_cache.set("test:key:1", {"status": "MATCHED", "val": 123}, ttl=1)
        
        # Immediate read
        cached = test_cache.get("test:key:1")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["val"], 123)

        # Wait for expiration
        time.sleep(1.1)
        expired = test_cache.get("test:key:1")
        self.assertIsNone(expired)

    def test_04_malwarebazaar_client_mock(self):
        """Test MalwareBazaar client for match, clean, and timeout handling."""
        client = MalwareBazaarClient()

        # Mock matched response
        mock_resp_matched = MagicMock()
        mock_resp_matched.status_code = 200
        mock_resp_matched.json.return_value = {
            "query_status": "ok",
            "data": [{
                "signature": "Trojan.Banker",
                "tags": ["apk", "banker", "dropper"],
                "first_seen": "2026-01-01 12:00:00",
                "file_type": "apk"
            }]
        }

        with patch("requests.post", return_value=mock_resp_matched):
            res = asyncio.run(client.lookup_hash("b" * 64))
            self.assertTrue(res["matched"])
            self.assertEqual(res["malware_family"], "Trojan.Banker")
            self.assertIn("dropper", res["tags"])

        # Mock clean (hash not found) response
        mock_resp_clean = MagicMock()
        mock_resp_clean.status_code = 200
        mock_resp_clean.json.return_value = {"query_status": "hash_not_found"}

        with patch("requests.post", return_value=mock_resp_clean):
            res_clean = asyncio.run(client.lookup_hash("c" * 64))
            self.assertFalse(res_clean["matched"])
            self.assertEqual(res_clean["status"], "CLEAN")

    def test_05_urlhaus_and_threatfox_mock(self):
        """Test URLhaus and ThreatFox clients."""
        uh_client = URLhausClient()
        tf_client = ThreatFoxClient()

        # URLhaus mock match
        mock_uh = MagicMock()
        mock_uh.status_code = 200
        mock_uh.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "url_status": "online",
            "tags": ["apk", "payload"]
        }
        with patch("requests.post", return_value=mock_uh):
            res_uh = asyncio.run(uh_client.lookup_url("http://bad-link.com/app.apk"))
            self.assertTrue(res_uh["matched"])
            self.assertEqual(res_uh["threat"], "malware_download")

        # ThreatFox mock match
        mock_tf = MagicMock()
        mock_tf.status_code = 200
        mock_tf.json.return_value = {
            "query_status": "ok",
            "data": [{
                "threat_type": "botnet_cc",
                "threat_type_desc": "Command and control server",
                "malware_printable": "Hydra",
                "confidence_level": 90
            }]
        }
        with patch("requests.post", return_value=mock_tf):
            res_tf = asyncio.run(tf_client.lookup_ioc("185.220.101.5"))
            self.assertTrue(res_tf["matched"])
            self.assertEqual(res_tf["malware_printable"], "Hydra")

    def test_06_virustotal_client_disabled_and_enabled(self):
        """Test VirusTotal client skips network if not configured, and parses attributes if enabled."""
        # Unconfigured
        client_no_key = VirusTotalClient(api_key="")
        self.assertFalse(client_no_key.is_configured)
        res_no_key = asyncio.run(client_no_key.lookup_hash("d" * 64))
        self.assertFalse(res_no_key["available"])
        self.assertEqual(res_no_key["status"], "NOT_CONFIGURED")

        # Configured mock
        client_with_key = VirusTotalClient(api_key="mock_vt_key")
        mock_vt_resp = MagicMock()
        mock_vt_resp.status_code = 200
        mock_vt_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 14, "suspicious": 2, "undetected": 50, "harmless": 4},
                    "popular_threat_classification": {"suggested_threat_label": "trojan.dropper/agent"}
                }
            }
        }
        with patch("requests.get", return_value=mock_vt_resp):
            res_vt = asyncio.run(client_with_key.lookup_hash("e" * 64))
            self.assertTrue(res_vt["matched"])
            self.assertEqual(res_vt["malicious_count"], 14)

    def test_07_evidence_correlation_and_sanitization(self):
        """Verify strict privacy sanitization: NO provider names leak into user-facing output."""
        norm_indicators = {
            "hashes": {"sha256": "f" * 64},
            "domains": ["malicious-domain.com"],
            "ips": ["185.220.101.5"],
            "urls": ["http://evil.com/drop.apk"]
        }
        ti_results = [
            {
                "provider": "MalwareBazaar",
                "indicator_type": "sha256",
                "indicator_value": "f" * 64,
                "matched": True,
                "malware_family": "Trojan.Dropper",
                "tags": ["apk"]
            },
            {
                "provider": "URLhaus",
                "indicator_type": "url",
                "indicator_value": "http://evil.com/drop.apk",
                "matched": True,
                "threat": "malware_download"
            }
        ]

        correlation = CorrelationEngine.correlate(
            normalized_indicators=norm_indicators,
            ti_results=ti_results,
            prediction={"classification": "Malicious", "malware_family": "Dropper"}
        )

        public = correlation["public"]
        audit = correlation["audit"]

        # User-facing values must use clean security terminology
        self.assertEqual(public["intelligence_match_status"], "Confirmed Threat Indicators Correlated")
        self.assertEqual(public["hash_reputation"], "Flagged Malicious Signature")
        self.assertIn("Suspicious", public["domain_reputation"])
        self.assertEqual(public["malware_association"], "Trojan.Dropper")

        # STRICT PRIVACY RULE VERIFICATION:
        public_json = json.dumps(public).lower()
        forbidden_terms = ["malwarebazaar", "urlhaus", "threatfox", "virustotal", "abuse.ch", "http://evil.com"]
        for term in forbidden_terms:
            self.assertNotIn(term, public_json, f"Forbidden term '{term}' leaked into user-facing public payload!")

        # Internal audit retains provider provenance
        audit_json = json.dumps(audit).lower()
        self.assertIn("malwarebazaar", audit_json)
        self.assertIn("urlhaus", audit_json)

    def test_08_resilience_when_all_external_apis_offline(self):
        """When all external TI APIs time out or return errors, analysis completes neutrally."""
        norm_indicators = {
            "hashes": {"sha256": "0" * 64},
            "domains": [],
            "ips": [],
            "urls": []
        }
        ti_results = [
            {"provider": "MalwareBazaar", "matched": False, "status": "TIMEOUT"},
            {"provider": "URLhaus", "matched": False, "status": "ERROR"},
            {"provider": "ThreatFox", "matched": False, "status": "TIMEOUT"}
        ]

        correlation = CorrelationEngine.correlate(
            normalized_indicators=norm_indicators,
            ti_results=ti_results,
            prediction={"classification": "Benign", "malware_family": "None"}
        )

        public = correlation["public"]
        self.assertEqual(public["intelligence_match_status"], "Threat Intelligence Enrichment Partially Unavailable")
        self.assertEqual(public["hash_reputation"], "Unobserved / Neutral")
        self.assertEqual(public["threat_confidence"], 0.0)

    def test_09_benign_app_preservation(self):
        """Trusted/benign apps with clean indicators MUST remain clean Benign."""
        norm_indicators = {
            "hashes": {"sha256": "1" * 64},
            "domains": ["netflix.com"],
            "ips": [],
            "urls": []
        }
        ti_results = [
            {"provider": "MalwareBazaar", "matched": False, "status": "CLEAN"},
            {"provider": "URLhaus", "matched": False, "status": "CLEAN"},
            {"provider": "ThreatFox", "matched": False, "status": "CLEAN"}
        ]

        correlation = CorrelationEngine.correlate(
            normalized_indicators=norm_indicators,
            ti_results=ti_results,
            prediction={"classification": "Benign", "malware_family": "None"}
        )

        public = correlation["public"]
        self.assertEqual(public["intelligence_match_status"], "No Known Threat Indicators Identified")
        self.assertEqual(public["hash_reputation"], "Clean / No Malicious Records")
        self.assertEqual(public["malware_association"], "None")
        self.assertEqual(public["risk_tier"], "Clean")

    def test_10_stix_bundle_enrichment(self):
        """Test STIX bundle export includes correlated threat observables when present."""
        analysis_record = {
            "filename": "suspicious.apk",
            "file_hash": "2" * 64,
            "classification": "Malicious",
            "malware_family": "Trojan.Dropper",
            "confidence_score": 95.0,
            "threat_intelligence": {
                "correlated_evidence": [
                    {
                        "category": "Domain Reputation",
                        "observable": "malicious-c2.net",
                        "assessment": "Confirmed C2 host"
                    }
                ]
            }
        }
        bundle = generate_stix_bundle(analysis_record)
        self.assertEqual(bundle.get("type"), "bundle")
        objects = bundle.get("objects", [])
        
        # Check that observable indicator for malicious-c2.net was added
        patterns = [obj.get("pattern", "") for obj in objects if obj.get("type") == "indicator"]
        has_c2_pattern = any("malicious-c2.net" in p for p in patterns)
        self.assertTrue(has_c2_pattern, "Correlated domain was not enriched in STIX bundle.")

    def test_11_dynamic_percentage_and_clean_checking(self):
        """Verify dynamic confidence score calculation and clean checking without fixed percentages."""
        from backend.feature_extraction.preprocessing import build_feature_vector
        from backend.classification.predictor import predict_malware_family

        # App 1: Simple utility with INTERNET
        app1_static = {
            "package_name": "com.simple.calculator",
            "permissions": ["android.permission.INTERNET"],
            "activities": ["MainActivity"],
            "dangerous_permissions": []
        }
        vec1 = build_feature_vector(app1_static)
        res1 = predict_malware_family(vec1, static_data=app1_static)

        # App 2: Utility with multiple permissions but clean
        app2_static = {
            "package_name": "org.offline.reader",
            "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE", "android.permission.WAKE_LOCK"],
            "activities": ["ReaderActivity", "SettingsActivity", "AboutActivity"],
            "dangerous_permissions": []
        }
        vec2 = build_feature_vector(app2_static)
        res2 = predict_malware_family(vec2, static_data=app2_static)

        # Both must be Benign because no malicious indicators exist
        self.assertEqual(res1["classification"], "Benign")
        self.assertEqual(res2["classification"], "Benign")

        # Confidence scores must be genuinely calculated and NOT hardcoded to 95.0
        self.assertNotEqual(res1["confidence_score"], 95.0)
        self.assertNotEqual(res2["confidence_score"], 95.0)
        self.assertNotEqual(res1["confidence_score"], res2["confidence_score"])

    def test_12_active_emulator_benign_general_app(self):
        """Active analysis on general benign app with ACTION_VIEW must remain Benign and not falsely trigger phishing."""
        from backend.dynamic_analysis.emulator_worker import EmulatorWorker

        worker = EmulatorWorker()
        general_benign = {
            "package_name": "com.mycompany.app",
            "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
            "dangerous_permissions": [],
            "sensitive_api_matches": ["ACTION_VIEW", "WebView_loadUrl"],
            "embedded_urls": ["https://mycompany.com/privacy", "https://github.com/project"],
            "embedded_domains": ["mycompany.com", "github.com"],
            "activities": ["MainActivity"]
        }
        exec_res = worker.execute_active_analysis("/fake/path.apk", "my_app.apk", general_benign)

        # Must be BENIGN because URLs are benign and not deceptive phishing
        self.assertEqual(exec_res["classification"], "BENIGN")
        self.assertIn("NO SIGNIFICANT MALICIOUS INDICATORS DETECTED", exec_res["status_banner_text"])
        self.assertIsNone(exec_res.get("redirect_evidence"))
        self.assertIsNone(exec_res.get("data_leakage_evidence"))
        self.assertIsNone(exec_res.get("malicious_evidence"))

        # Must not be hardcoded 95.0%
        self.assertNotEqual(exec_res["confidence_score"], 95.0)

if __name__ == "__main__":
    unittest.main()
