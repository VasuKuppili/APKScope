import os
import sys
import json
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.main import app
from backend.database.connection import SessionLocal
from backend.database.models import AnalysisRecord, TaxiiConfig
from backend.threat_intelligence.stix_generator import generate_stix_bundle

class TestStixTaxiiIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Seed completed malicious record for STIX testing
        cls.record_id = "test-job-stix-001"
        existing = cls.db.query(AnalysisRecord).filter(AnalysisRecord.id == cls.record_id).first()
        if existing:
            cls.db.delete(existing)
            cls.db.commit()

        cls.test_record = AnalysisRecord(
            id=cls.record_id,
            filename="ransomware_sample.apk",
            file_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            file_size=2097152,
            file_path="backend/uploads/ransomware_sample.apk",
            analysis_mode="active",
            status="COMPLETED",
            progress=100,
            status_message="Active sandbox analysis completed.",
            classification="Malicious",
            malware_family="Ransomware",
            confidence_score=98.1,
            extracted_features=json.dumps({
                "package_name": "com.locker.ransom",
                "permissions": ["android.permission.BIND_DEVICE_ADMIN", "android.permission.WRITE_EXTERNAL_STORAGE"],
                "sensitive_api_matches": ["Ljavax/crypto/Cipher;->getInstance", "Landroid/app/admin/DevicePolicyManager;->lockNow"],
                "dynamic_telemetry": {
                    "dyn_file_encryption_ops": 150.0,
                    "dyn_file_delete_ops": 40.0
                }
            }),
            shap_explanation=json.dumps({
                "top_features": [
                    {"name": "Ljavax/crypto/Cipher;->getInstance", "shap_value": 0.45, "importance": 42.0},
                    {"name": "dyn_file_encryption_ops", "shap_value": 0.38, "importance": 35.0}
                ],
                "category_breakdown": [
                    {"category": "File Operations", "percentage": 50.0},
                    {"category": "Sensitive API Calls", "percentage": 30.0},
                    {"category": "Process & System Execution", "percentage": 20.0}
                ]
            }),
            behavior_summary="Detected active file encryption operations and administrative device locking."
        )
        cls.db.add(cls.test_record)
        cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        rec = cls.db.query(AnalysisRecord).filter(AnalysisRecord.id == cls.record_id).first()
        if rec:
            cls.db.delete(rec)
            cls.db.commit()
        cls.db.close()

    def test_01_stix_bundle_generation(self):
        """FR-09: Generate structured STIX 2.1 bundle with Indicator, Malware, and Relationship objects"""
        res = self.client.get(f"/api/results/{self.record_id}/stix")
        self.assertEqual(res.status_code, 200)
        bundle = res.json()

        self.assertEqual(bundle.get("type"), "bundle")
        self.assertIn("objects", bundle)
        objects = bundle["objects"]

        types = [obj["type"] for obj in objects]
        self.assertIn("identity", types)
        self.assertIn("indicator", types)
        self.assertIn("malware", types)
        self.assertIn("relationship", types)

        # Check indicator pattern contains the SHA-256 hash
        indicator = next(o for o in objects if o["type"] == "indicator")
        self.assertIn(self.test_record.file_hash, indicator["pattern"])
        self.assertEqual(indicator["pattern_type"], "stix")

        # Check malware object reflects family name
        malware = next(o for o in objects if o["type"] == "malware")
        self.assertEqual(malware["name"], "Ransomware")
        self.assertTrue(malware["is_family"])

    def test_02_taxii_configuration_persistence(self):
        """FR-10: Save and retrieve TAXII 2.1 server configuration"""
        cfg_payload = {
            "server_url": "https://threatintel.local/taxii2/",
            "collection_id": "android-ioc-collection",
            "username": "analyst_sec",
            "password": "secret_password",
            "use_https": True
        }
        post_res = self.client.post("/api/taxii/config", json=cfg_payload)
        self.assertEqual(post_res.status_code, 200)
        self.assertEqual(post_res.json()["status"], "success")

        get_res = self.client.get("/api/taxii/config")
        self.assertEqual(get_res.status_code, 200)
        data = get_res.json()
        self.assertTrue(data["configured"])
        self.assertEqual(data["server_url"], "https://threatintel.local/taxii2/")
        self.assertEqual(data["collection_id"], "android-ioc-collection")
        self.assertEqual(data["username"], "analyst_sec")

    def test_03_taxii_test_connection_offline_fails_gracefully(self):
        """FR-10: Test TAXII connection returns clean 502/400 without crashing on unreachable server"""
        res = self.client.post("/api/taxii/test")
        # Since dummy server is unreachable, it should return 502 with informative message
        self.assertEqual(res.status_code, 502)
        self.assertIn("TAXII Server connection failed", res.json()["detail"])

        # DB status should reflect ERROR
        db = SessionLocal()
        cfg = db.query(TaxiiConfig).first()
        self.assertEqual(cfg.status, "ERROR")
        db.close()

if __name__ == "__main__":
    unittest.main()
