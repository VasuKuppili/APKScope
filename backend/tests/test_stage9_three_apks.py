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
from backend.routes.passive import run_passive_pipeline
from backend.routes.active import run_active_pipeline

class TestThreeApkTestCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import logging
        for logger_name in ["androguard", "androguard.core.axml", "androguard.core.apk", "androguard.core.bytecodes.dvm"]:
            logging.getLogger(logger_name).setLevel(logging.ERROR)
        os.environ["FAST_TEST_MODE"] = "1"
        cls.client = TestClient(app)
        cls.test_dir = os.path.join(os.path.dirname(__file__), "test_apks_three")
        os.makedirs(cls.test_dir, exist_ok=True)

        # Locate NetMirror and VidMate APKs
        workspace_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        uploads_dir = os.path.join(workspace_root, "uploads")
        
        cls.netmirror_path = None
        cls.vidmate_path = None
        
        if os.path.exists(uploads_dir):
            for f in os.listdir(uploads_dir):
                if "NetMirror" in f and f.endswith(".apk") and not cls.netmirror_path:
                    cls.netmirror_path = os.path.join(uploads_dir, f)
                elif "vidmate" in f and f.endswith(".apk") and not cls.vidmate_path:
                    cls.vidmate_path = os.path.join(uploads_dir, f)

        # Fallback to Downloads if not in uploads
        downloads_dir = r"C:\Users\USER\Downloads"
        if not cls.netmirror_path and os.path.exists(os.path.join(downloads_dir, "NetMirror_Updated.apk")):
            cls.netmirror_path = os.path.join(downloads_dir, "NetMirror_Updated.apk")
        if not cls.vidmate_path and os.path.exists(os.path.join(downloads_dir, "vidmate_v6.0302_20260911110128_encrypt.apk")):
            cls.vidmate_path = os.path.join(downloads_dir, "vidmate_v6.0302_20260911110128_encrypt.apk")

        # Create Cricfy test APK
        cls.cricfy_path = os.path.join(cls.test_dir, "cricfy_v4.2.apk")
        with zipfile.ZipFile(cls.cricfy_path, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.cricfy.tv.player"><application android:name=".CricfyApp"><activity android:name=".MainActivity"><intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter></activity></application></manifest>')
            dex_bytes = bytearray(b"DEX_HEADER_CRICFY\x00")
            dex_bytes.extend(b"android.permission.INTERNET\x00")
            dex_bytes.extend(b"android.permission.ACCESS_NETWORK_STATE\x00")
            dex_bytes.extend(b"android.intent.action.VIEW\x00")
            dex_bytes.extend(b"androidx/browser/customtabs/CustomTabsIntent\x00")
            dex_bytes.extend(b"https://track.adclick-redirect.net/stream?auth=session_token\x00")
            z.writestr("classes.dex", bytes(dex_bytes))

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("FAST_TEST_MODE", None)

    # -------------------------------------------------------------
    # Scenario 1: CRICFY - Passive Analysis
    # -------------------------------------------------------------
    def test_01_cricfy_passive_analysis(self):
        """CRICFY PASSIVE: Validate APK, extract static features, assert NO SIGNIFICANT STATIC THREATS DETECTED"""
        with open(self.cricfy_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("cricfy_v4.2.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]
        sha256 = upload_res.json()["sha256"]
        self.assertEqual(len(sha256), 64)

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification.upper(), "BENIGN")
        
        feat = rec_updated.to_dict()["extracted_features"] or {}
        self.assertIn("NO SIGNIFICANT STATIC THREATS DETECTED", feat.get("status_banner_text", ""))
        self.assertIn("passive analysis", rec_updated.behavior_summary.lower())
        db.close()

        # Verify PDF report generation
        pdf_res = self.client.get(f"/api/reports/{job_id}?format=pdf")
        self.assertEqual(pdf_res.status_code, 200)

        # Verify History entry
        hist_res = self.client.get(f"/api/history?search={sha256[:10]}")
        self.assertEqual(hist_res.status_code, 200)
        self.assertGreaterEqual(hist_res.json()["total"], 1)

    # -------------------------------------------------------------
    # Scenario 2: CRICFY - Active Analysis
    # -------------------------------------------------------------
    def test_02_cricfy_active_analysis(self):
        """CRICFY ACTIVE: Isolated sandbox execution, controlled UI touch, assert PHISHING / SUSPICIOUS REDIRECT"""
        with open(self.cricfy_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("cricfy_active_test.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_active_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification, "PHISHING / SUSPICIOUS REDIRECT")

        feat = rec_updated.to_dict()["extracted_features"] or {}
        redirect_ev = feat.get("redirect_evidence")
        self.assertIsNotNone(redirect_ev)
        self.assertIn("redirect_destination", redirect_ev)
        self.assertIn("original_activity", redirect_ev)
        self.assertIn("triggering_action", redirect_ev)
        self.assertIn("redirect_url", redirect_ev)
        self.assertEqual(redirect_ev["risk_level"], "High")
        db.close()

    # -------------------------------------------------------------
    # Scenario 3: NETMIRROR - Passive Analysis
    # -------------------------------------------------------------
    def test_03_netmirror_passive_analysis(self):
        """NETMIRROR PASSIVE: Inspect permissions & APIs, assert NO SIGNIFICANT STATIC THREATS DETECTED"""
        if not self.netmirror_path or not os.path.exists(self.netmirror_path):
            self.skipTest("NetMirror_Updated.apk not found in workspace.")

        with open(self.netmirror_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("NetMirror_Updated.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification.upper(), "BENIGN")

        feat = rec_updated.to_dict()["extracted_features"] or {}
        self.assertIn("NO SIGNIFICANT STATIC THREATS DETECTED", feat.get("status_banner_text", ""))
        db.close()

    # -------------------------------------------------------------
    # Scenario 4: NETMIRROR - Active Analysis
    # -------------------------------------------------------------
    def test_04_netmirror_active_analysis(self):
        """NETMIRROR ACTIVE: Monitor runtime network & data access, assert DATA LEAKAGE / PRIVACY RISK"""
        if not self.netmirror_path or not os.path.exists(self.netmirror_path):
            self.skipTest("NetMirror_Updated.apk not found in workspace.")

        with open(self.netmirror_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("NetMirror_active.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_active_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification, "DATA LEAKAGE / PRIVACY RISK")

        feat = rec_updated.to_dict()["extracted_features"] or {}
        leakage_ev = feat.get("data_leakage_evidence")
        self.assertIsNotNone(leakage_ev)
        self.assertIn("information_accessed", leakage_ev)
        self.assertIn("actually_transmitted", leakage_ev)
        self.assertIn("destination_domain_or_ip", leakage_ev)
        self.assertEqual(leakage_ev["risk_severity"], "High")
        db.close()

    # -------------------------------------------------------------
    # Scenario 5: VIDMATE - Passive Analysis
    # -------------------------------------------------------------
    def test_05_vidmate_passive_analysis(self):
        """VIDMATE PASSIVE: Inspect high-risk permissions & DCL, assert MALICIOUS / SUSPICIOUS INDICATORS DETECTED"""
        if not self.vidmate_path or not os.path.exists(self.vidmate_path):
            self.skipTest("vidmate APK not found in workspace.")

        with open(self.vidmate_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("vidmate_test.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification.upper(), "MALICIOUS")

        feat = rec_updated.to_dict()["extracted_features"] or {}
        self.assertIn("MALICIOUS / SUSPICIOUS INDICATORS DETECTED", feat.get("status_banner_text", ""))
        db.close()

    # -------------------------------------------------------------
    # Scenario 6: VIDMATE - Active Analysis
    # -------------------------------------------------------------
    def test_06_vidmate_active_analysis(self):
        """VIDMATE ACTIVE: Monitor runtime background activity & installs, assert MALICIOUS BEHAVIOUR DETECTED"""
        if not self.vidmate_path or not os.path.exists(self.vidmate_path):
            self.skipTest("vidmate APK not found in workspace.")

        with open(self.vidmate_path, "rb") as f:
            upload_res = self.client.post("/api/upload", files={"file": ("vidmate_active.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(upload_res.status_code, 200)
        job_id = upload_res.json()["job_id"]

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_active_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification.upper(), "MALICIOUS")

        feat = rec_updated.to_dict()["extracted_features"] or {}
        mal_ev = feat.get("malicious_evidence")
        self.assertIsNotNone(mal_ev)
        self.assertIn("observed_behavior", mal_ev)
        self.assertEqual(mal_ev["risk_level"], "Critical")
        db.close()

    # -------------------------------------------------------------
    # Edge Cases & Negative Scenarios
    # -------------------------------------------------------------
    def test_07_invalid_apk_rejected(self):
        """Reject non-APK extension"""
        res = self.client.post("/api/upload", files={"file": ("document.pdf", b"PDF_DATA", "application/pdf")})
        self.assertEqual(res.status_code, 400)

    def test_08_corrupted_apk_rejected(self):
        """Reject corrupted non-zip binary renamed to .apk"""
        res = self.client.post("/api/upload", files={"file": ("corrupt.apk", b"NOT_A_ZIP", "application/vnd.android.package-archive")})
        self.assertIn(res.status_code, [400, 422])

    def test_09_duplicate_apk_detected(self):
        """Duplicate SHA-256 hash detection returns existing analysis record"""
        with open(self.cricfy_path, "rb") as f:
            res1 = self.client.post("/api/upload", files={"file": ("cricfy_v4.2.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(res1.status_code, 200)

        with open(self.cricfy_path, "rb") as f:
            res2 = self.client.post("/api/upload", files={"file": ("cricfy_copy.apk", f, "application/vnd.android.package-archive")})
        self.assertEqual(res2.status_code, 200)
        self.assertTrue(res2.json()["is_duplicate"])
        self.assertIsNotNone(res2.json()["existing_analysis_id"])

    def test_10_emulator_unavailable_handling(self):
        """When STRICT_EMULATOR_REQUIRED=1 and no emulator is connected, Active Analysis fails safely"""
        os.environ["STRICT_EMULATOR_REQUIRED"] = "1"
        try:
            with open(self.cricfy_path, "rb") as f:
                res = self.client.post("/api/upload", files={"file": ("strict_emu_test.apk", f, "application/vnd.android.package-archive")})
            job_id = res.json()["job_id"]
            
            db = SessionLocal()
            rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
            file_path, filename = rec.file_path, rec.filename
            db.close()

            asyncio.run(run_active_pipeline(job_id, file_path, filename))

            db = SessionLocal()
            rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
            self.assertEqual(rec_updated.status, "FAILED")
            self.assertEqual(rec_updated.classification, "ANALYSIS FAILED")
            db.close()
        finally:
            os.environ.pop("STRICT_EMULATOR_REQUIRED", None)

    def test_11_insufficient_evidence_inconclusive(self):
        """Verify that an ambiguous APK with no indicators returns Unknown / Inconclusive"""
        ambiguous_path = os.path.join(self.test_dir, "ambiguous_empty.apk")
        with zipfile.ZipFile(ambiguous_path, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.ambiguous.empty"></manifest>')
            z.writestr("classes.dex", b"DEX_EMPTY\x00")

        with open(ambiguous_path, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("ambiguous_empty.apk", f, "application/vnd.android.package-archive")})
        job_id = res.json()["job_id"]

        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path, filename = rec.file_path, rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertIn(rec_updated.classification.upper(), ["BENIGN", "UNKNOWN", "UNKNOWN / INCONCLUSIVE"])
        db.close()
