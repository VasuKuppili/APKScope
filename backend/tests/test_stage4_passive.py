import os
import sys
import zipfile
import asyncio
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient
from backend.main import app
from backend.database.connection import SessionLocal
from backend.database.models import AnalysisRecord
from backend.routes.passive import run_passive_pipeline

class TestPassiveAnalysisPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["FAST_TEST_MODE"] = "1"
        cls.client = TestClient(app)
        cls.temp_dir = os.path.join(os.path.dirname(__file__), "test_apks")
        os.makedirs(cls.temp_dir, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("FAST_TEST_MODE", None)

    def _create_apk(self, filename: str, permissions: list, api_strings: list, has_manifest=True, corrupt_zip=False):
        path = os.path.join(self.temp_dir, filename)
        if corrupt_zip:
            with open(path, "wb") as f:
                f.write(b"NOT_A_VALID_ZIP_MAGIC_BYTES_1234567890")
            return path

        with zipfile.ZipFile(path, "w") as z:
            if has_manifest:
                z.writestr("AndroidManifest.xml", b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app"></manifest>')
            
            # Pack permissions and API strings into classes.dex raw bytes
            dex_bytes = bytearray(b"DEX_HEADER_MOCK\x00")
            for p in permissions:
                dex_bytes.extend(p.encode("utf-8") + b"\x00")
            for a in api_strings:
                dex_bytes.extend(a.encode("utf-8") + b"\x00")
            
            z.writestr("classes.dex", bytes(dex_bytes))
        return path

    def test_01_invalid_extension_rejected(self):
        """FR-01/FR-02: Non-apk extensions must be rejected"""
        dummy_path = os.path.join(self.temp_dir, "malware.exe")
        with open(dummy_path, "wb") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00")
        
        with open(dummy_path, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("malware.exe", f, "application/octet-stream")})
        
        self.assertEqual(res.status_code, 400)
        self.assertIn("must have an .apk extension", res.json()["detail"])
        if os.path.exists(dummy_path):
            os.remove(dummy_path)

    def test_02_invalid_file_renamed_to_apk_rejected(self):
        """FR-02: Non-zip binary renamed to .apk must be rejected by magic byte check"""
        fake_apk = self._create_apk("fake_text.apk", [], [], corrupt_zip=True)
        with open(fake_apk, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("fake_text.apk", f, "application/vnd.android.package-archive")})
        
        self.assertEqual(res.status_code, 422)
        self.assertIn("not a valid zip/APK archive", res.json()["detail"])
        if os.path.exists(fake_apk):
            os.remove(fake_apk)

    def test_03_missing_manifest_rejected(self):
        """FR-02: Valid zip without AndroidManifest.xml must be rejected"""
        no_manifest_apk = self._create_apk("no_manifest.apk", [], [], has_manifest=False)
        with open(no_manifest_apk, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("no_manifest.apk", f, "application/vnd.android.package-archive")})
        
        self.assertEqual(res.status_code, 422)
        self.assertIn("missing AndroidManifest.xml", res.json()["detail"])
        if os.path.exists(no_manifest_apk):
            os.remove(no_manifest_apk)

    def test_04_valid_upload_and_sha256_calculation(self):
        """FR-03: SHA-256 calculation on valid upload"""
        valid_apk = self._create_apk(
            "valid_sample.apk",
            ["android.permission.INTERNET"],
            ["HttpURLConnection"]
        )
        with open(valid_apk, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("valid_sample.apk", f, "application/vnd.android.package-archive")})
        
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["has_dex"])
        self.assertEqual(len(data["file_hash"]), 64)
        self.assertFalse(data["is_duplicate"])
        self.valid_job_id = data["job_id"]
        if os.path.exists(valid_apk):
            os.remove(valid_apk)

    def test_05_sha256_duplicate_detection(self):
        """FR-03: Duplicate APKs must be identified by hash"""
        dup_apk = self._create_apk(
            "dup_sample.apk",
            ["android.permission.INTERNET"],
            ["HttpURLConnection"]
        )
        # Upload first
        with open(dup_apk, "rb") as f:
            res1 = self.client.post("/api/upload", files={"file": ("dup_sample.apk", f, "application/vnd.android.package-archive")})
        job1 = res1.json()["job_id"]

        # Run analysis to completion
        db = SessionLocal()
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == job1).first()
        asyncio.run(run_passive_pipeline(record.id, record.file_path, record.filename))
        db.close()

        # Upload duplicate with different name
        with open(dup_apk, "rb") as f:
            res2 = self.client.post("/api/upload", files={"file": ("renamed_dup.apk", f, "application/vnd.android.package-archive")})
        
        self.assertEqual(res2.status_code, 200)
        data2 = res2.json()
        self.assertTrue(data2["is_duplicate"])
        self.assertEqual(data2["existing_analysis_id"], job1)
        if os.path.exists(dup_apk):
            os.remove(dup_apk)

    def test_06_benign_apk_classification(self):
        """FR-06/FR-07: Benign application profile classified as safe"""
        benign_apk = self._create_apk(
            "benign_calculator.apk",
            ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
            ["HttpURLConnection"]
        )
        with open(benign_apk, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("benign_calculator.apk", f, "application/vnd.android.package-archive")})
        
        job_id = res.json()["job_id"]
        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path = rec.file_path
        filename = rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification, "Benign")
        self.assertGreaterEqual(rec_updated.confidence_score, 80.0)
        self.assertIsNotNone(rec_updated.shap_explanation)
        db.close()
        if os.path.exists(benign_apk):
            os.remove(benign_apk)

    def test_07_trojan_banker_classification(self):
        """FR-06/FR-07: Trojan Banker profile (SMS, Accessibility, Overlay) classified as Malicious"""
        trojan_apk = self._create_apk(
            "bank_fake_update.apk",
            [
                "android.permission.INTERNET",
                "android.permission.READ_PHONE_STATE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS"
            ],
            [
                "sendTextMessage",
                "DexClassLoader",
                "getDeviceId"
            ]
        )
        with open(trojan_apk, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("bank_fake_update.apk", f, "application/vnd.android.package-archive")})
        
        job_id = res.json()["job_id"]
        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path = rec.file_path
        filename = rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification, "Malicious")
        self.assertEqual(rec_updated.malware_family, "Trojan.Banker")
        self.assertGreaterEqual(rec_updated.confidence_score, 85.0)
        db.close()
        if os.path.exists(trojan_apk):
            os.remove(trojan_apk)

    def test_08_ransomware_classification(self):
        """FR-06/FR-07: Ransomware profile (Device Admin, Storage, Cipher API) classified as Malicious"""
        ransom_apk = self._create_apk(
            "locker_sample.apk",
            [
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            [
                "Cipher",
                "DevicePolicyManager"
            ]
        )
        with open(ransom_apk, "rb") as f:
            res = self.client.post("/api/upload", files={"file": ("locker_sample.apk", f, "application/vnd.android.package-archive")})
        
        job_id = res.json()["job_id"]
        db = SessionLocal()
        rec = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        file_path = rec.file_path
        filename = rec.filename
        db.close()

        asyncio.run(run_passive_pipeline(job_id, file_path, filename))

        db = SessionLocal()
        rec_updated = db.query(AnalysisRecord).filter(AnalysisRecord.id == job_id).first()
        
        self.assertEqual(rec_updated.status, "COMPLETED")
        self.assertEqual(rec_updated.classification, "Malicious")
        self.assertEqual(rec_updated.malware_family, "Ransomware")
        db.close()
        if os.path.exists(ransom_apk):
            os.remove(ransom_apk)

    @classmethod
    def tearDownClass(cls):
        import shutil
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
