import os
import sys
import zipfile
import asyncio
import unittest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.main import app
from backend.database.connection import SessionLocal
from backend.database.models import AnalysisRecord
from backend.routes.active import run_active_pipeline

class TestActiveDynamicAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["FAST_TEST_MODE"] = "1"
        cls.client = TestClient(app)
        cls.temp_dir = os.path.join(os.path.dirname(__file__), "test_apks_active")
        os.makedirs(cls.temp_dir, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("FAST_TEST_MODE", None)

    def _create_apk(self, filename: str, permissions: list, api_strings: list):
        path = os.path.join(self.temp_dir, filename)
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.active.test"></manifest>')
            dex_bytes = bytearray(b"DEX_HEADER_MOCK\x00")
            for p in permissions:
                dex_bytes.extend(p.encode("utf-8") + b"\x00")
            for a in api_strings:
                dex_bytes.extend(a.encode("utf-8") + b"\x00")
            z.writestr("classes.dex", bytes(dex_bytes))
        return path

    def test_01_active_pipeline_execution(self):
        """FR-05: Execute isolated dynamic sandbox analysis and verify telemetry + classification"""
        apk_path = self._create_apk(
            "active_banker.apk",
            permissions=[
                "android.permission.INTERNET",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            api_strings=[
                "Landroid/telephony/SmsManager;->sendTextMessage",
                "Ldalvik/system/DexClassLoader;-><init>"
            ]
        )

        # Upload file first
        with open(apk_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("active_banker.apk", f, "application/octet-stream")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]

        # Trigger active analysis
        res = self.client.post("/api/active/analyze", json={"job_id": job_id})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "started")
        self.assertEqual(res.json()["mode"], "active")

        # Run pipeline to completion
        asyncio.run(run_active_pipeline(job_id, apk_path, "active_banker.apk"))

        # Verify database record
        db = SessionLocal()
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.status, "COMPLETED")
        self.assertEqual(record.progress, 100)
        self.assertEqual(record.classification, "Malicious")
        self.assertEqual(record.malware_family, "Trojan.Banker")

        # Verify dynamic telemetry is present in extracted features
        data = record.to_dict()
        features = data.get("extracted_features", {})
        self.assertIn("dynamic_telemetry", features)
        dyn = features["dynamic_telemetry"]
        self.assertGreater(dyn.get("dyn_sms_intercept_attempts", 0), 0)
        self.assertGreater(dyn.get("dyn_screen_overlay_events", 0), 0)

        # Verify SHAP explanation exists
        shap_res = data.get("shap_explanation", {})
        self.assertIn("top_features", shap_res)
        self.assertIn("category_breakdown", shap_res)

        db.delete(record)
        db.commit()
        db.close()

    def test_02_active_pipeline_cancellation(self):
        """FR-05 & UI cancel button: Terminate active sandbox job safely"""
        apk_path = self._create_apk("active_cancel.apk", ["android.permission.INTERNET"], [])
        with open(apk_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("active_cancel.apk", f, "application/octet-stream")})
        job_id = upload_res.json()["job_id"]

        self.client.post("/api/active/analyze", json={"job_id": job_id})

        # Cancel active job via jobs endpoint
        cancel_res = self.client.post(f"/api/jobs/{job_id}/cancel")
        self.assertEqual(cancel_res.status_code, 200)
        self.assertEqual(cancel_res.json()["status"], "success")

        # Verify database status is CANCELLED
        db = SessionLocal()
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(record.status, "CANCELLED")
        db.delete(record)
        db.commit()
        db.close()

if __name__ == "__main__":
    unittest.main()
