import unittest
import os
import zipfile
import numpy as np

from backend.static_analysis.extractor import extract_static_features
from backend.feature_extraction.preprocessing import build_feature_vector
from backend.classification.predictor import predict_malware_family
from backend.dynamic_analysis.emulator_worker import EmulatorWorker

class TestPrototypeVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = os.path.join(os.path.dirname(__file__), "test_apks_stage11")
        os.makedirs(cls.test_dir, exist_ok=True)

        # 1. Benign Utility App A (Flashlight / Calculator)
        cls.app_a_path = os.path.join(cls.test_dir, "utility_calc.apk")
        with zipfile.ZipFile(cls.app_a_path, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest package="com.utility.calculator"><application android:name=".CalcApp"><activity android:name=".MainActivity"/></application></manifest>')
            dex = bytearray(b"DEX_CALC_BYTES\x00")
            dex.extend(b"android.permission.INTERNET\x00")
            z.writestr("classes.dex", bytes(dex))

        # 2. Benign Utility App B (Notes / Reader)
        cls.app_b_path = os.path.join(cls.test_dir, "simple_notes.apk")
        with zipfile.ZipFile(cls.app_b_path, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest package="org.simple.notes"><application android:name=".NotesApp"><activity android:name=".NotesActivity"/></application></manifest>')
            dex = bytearray(b"DEX_NOTES_BYTES\x00")
            dex.extend(b"android.permission.ACCESS_NETWORK_STATE\x00")
            z.writestr("classes.dex", bytes(dex))

        # 3. Malicious Trojan Banker APK
        cls.banker_path = os.path.join(cls.test_dir, "trojan_banker.apk")
        with zipfile.ZipFile(cls.banker_path, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest package="com.quick.update"><application android:name=".App"><activity android:name=".Main"/></application></manifest>')
            dex = bytearray(b"DEX_BANKER_BYTES\x00")
            dex.extend(b"android.permission.SEND_SMS\x00")
            dex.extend(b"android.permission.RECEIVE_SMS\x00")
            dex.extend(b"android.permission.SYSTEM_ALERT_WINDOW\x00")
            dex.extend(b"android.permission.BIND_ACCESSIBILITY_SERVICE\x00")
            dex.extend(b"Landroid/telephony/SmsManager;->sendTextMessage\x00")
            z.writestr("classes.dex", bytes(dex))

    def test_01_two_different_benign_apps_have_unique_confidence(self):
        """Verify different benign apps receive distinct, dynamic confidence scores rather than static values."""
        stat_a = extract_static_features(self.app_a_path)
        vec_a = build_feature_vector(stat_a)
        pred_a = predict_malware_family(vec_a, static_data=stat_a)

        stat_b = extract_static_features(self.app_b_path)
        vec_b = build_feature_vector(stat_b)
        pred_b = predict_malware_family(vec_b, static_data=stat_b)

        # Both must be Benign
        self.assertEqual(pred_a["classification"], "Benign")
        self.assertEqual(pred_b["classification"], "Benign")

        # They must have distinct confidence scores based on package name, hash, and component footprints
        self.assertNotEqual(pred_a["confidence_score"], pred_b["confidence_score"])
        self.assertNotEqual(pred_a["confidence_score"], 95.0)
        self.assertNotEqual(pred_b["confidence_score"], 95.0)

    def test_02_harmful_only_if_threats_found(self):
        """Verify apps without malicious indicators are classified as Benign, and malicious apps are flagged."""
        # Clean app
        stat_clean = extract_static_features(self.app_a_path)
        vec_clean = build_feature_vector(stat_clean)
        pred_clean = predict_malware_family(vec_clean, static_data=stat_clean)
        self.assertEqual(pred_clean["classification"], "Benign")

        # Banker app with SMS fraud & overlay attack vectors
        stat_banker = extract_static_features(self.banker_path)
        vec_banker = build_feature_vector(stat_banker)
        pred_banker = predict_malware_family(vec_banker, static_data=stat_banker)
        self.assertEqual(pred_banker["classification"], "Malicious")
        self.assertIn("Banker", pred_banker["malware_family"])

    def test_03_active_analysis_distinct_results(self):
        """Verify active analysis dynamic emulator produces realistic and varying results."""
        worker = EmulatorWorker()

        stat_a = extract_static_features(self.app_a_path)
        active_a = worker.execute_active_analysis(self.app_a_path, "utility_calc.apk", stat_a)

        stat_banker = extract_static_features(self.banker_path)
        active_banker = worker.execute_active_analysis(self.banker_path, "trojan_banker.apk", stat_banker)

        # Utility app is BENIGN in sandbox
        self.assertEqual(active_a["classification"], "BENIGN")
        self.assertNotEqual(active_a["confidence_score"], 95.0)

        # Both have event timelines
        self.assertGreater(len(active_a["event_timeline"]), 0)
        self.assertGreater(len(active_banker["event_timeline"]), 0)

if __name__ == "__main__":
    unittest.main()
