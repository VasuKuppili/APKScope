import os
import sys
import json
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.main import app
from backend.database.connection import SessionLocal
from backend.database.models import AnalysisRecord

class TestReportsAndGemini(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Seed completed malicious record for report testing
        cls.record_id = "test-job-report-001"
        existing = cls.db.query(AnalysisRecord).filter(AnalysisRecord.id == cls.record_id).first()
        if existing:
            cls.db.delete(existing)
            cls.db.commit()

        cls.test_record = AnalysisRecord(
            id=cls.record_id,
            filename="trojan_banker_sample.apk",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size=1048576,
            file_path="backend/uploads/trojan_banker_sample.apk",
            analysis_mode="passive",
            status="COMPLETED",
            progress=100,
            status_message="Analysis completed successfully.",
            classification="Malicious",
            malware_family="Trojan.Banker",
            confidence_score=97.4,
            extracted_features=json.dumps({
                "package_name": "com.fraud.banker",
                "activity_count": 5,
                "service_count": 3,
                "receiver_count": 2,
                "provider_count": 0,
                "intent_filter_count": 6,
                "dangerous_permissions": ["SEND_SMS", "RECEIVE_SMS", "SYSTEM_ALERT_WINDOW"],
                "permissions": ["android.permission.INTERNET", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
                "sensitive_api_matches": ["Landroid/telephony/SmsManager;->sendTextMessage"]
            }),
            shap_explanation=json.dumps({
                "top_features": [
                    {"name": "android.permission.SEND_SMS", "value": 1.0, "shap_value": 0.42, "importance": 38.5},
                    {"name": "Landroid/telephony/SmsManager;->sendTextMessage", "value": 1.0, "shap_value": 0.35, "importance": 32.1},
                    {"name": "android.permission.SYSTEM_ALERT_WINDOW", "value": 1.0, "shap_value": 0.21, "importance": 19.3}
                ],
                "category_breakdown": [
                    {"category": "Permissions & Manifest", "percentage": 45.0},
                    {"category": "Sensitive API Calls", "percentage": 35.0},
                    {"category": "Network Behavior", "percentage": 20.0}
                ],
                "base_value": 0.16
            }),
            behavior_summary="Detected high-risk capabilities matching the Trojan.Banker family footprint."
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

    def test_01_download_report_json(self):
        """FR-11: Download structured analysis report in JSON format"""
        res = self.client.get(f"/api/reports/{self.record_id}?format=json")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("content-type"), "application/json")
        data = res.json()
        self.assertEqual(data["id"], self.record_id)
        self.assertEqual(data["classification"], "Malicious")
        self.assertEqual(data["malware_family"], "Trojan.Banker")
        self.assertIn("shap_explanation", data)

    def test_02_download_report_pdf(self):
        """FR-11: Download structured professional PDF report with ReportLab"""
        res = self.client.get(f"/api/reports/{self.record_id}?format=pdf")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("content-type"), "application/pdf")
        content = res.content
        # PDF magic bytes
        self.assertTrue(content.startswith(b"%PDF-"), "Generated file does not have valid PDF magic bytes")
        self.assertGreater(len(content), 2000, "PDF content is too small to be valid")

    def test_03_gemini_without_key_returns_400(self):
        """FR-08: Gemini explanation endpoint cleanly rejects when key is unset"""
        old_key = os.environ.pop("GEMINI_API_KEY", None)
        try:
            res = self.client.post(f"/api/results/{self.record_id}/gemini-explanation")
            self.assertEqual(res.status_code, 400)
            self.assertIn("Gemini API Key is not configured", res.json()["detail"])
        finally:
            if old_key:
                os.environ["GEMINI_API_KEY"] = old_key

    def test_04_gemini_settings_test_without_key_returns_400(self):
        """Settings button: Test Gemini API cleanly handles missing key"""
        old_key = os.environ.pop("GEMINI_API_KEY", None)
        try:
            res = self.client.post("/api/settings/gemini/test", json={"api_key": ""})
            self.assertEqual(res.status_code, 400)
        finally:
            if old_key:
                os.environ["GEMINI_API_KEY"] = old_key

if __name__ == "__main__":
    unittest.main()
