import unittest
import os
import zipfile
import shutil
import tempfile
from backend.static_analysis.styk_apk_tester import (
    parse_apk_signing_block,
    assess_certificate_trust_level,
    assess_signature_algorithm,
    assess_target_sdk_threshold,
    assess_manifest_and_components,
    test_apk_security_suite
)
from backend.static_analysis.extractor import extract_static_features


class TestMartinStykApkTester(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp()
        cls.v1_only_apk = os.path.join(cls.test_dir, "v1_only.apk")
        with zipfile.ZipFile(cls.v1_only_apk, "w") as z:
            z.writestr("AndroidManifest.xml", b'<manifest package="com.test.v1"/>')
            z.writestr("classes.dex", b"DEX\n035\x00")
            z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
            z.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x00")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def setUp(self):
        self.clean_apk = os.path.join("backend", "tests", "test_apks_stage11", "simple_notes.apk")
        self.malicious_apk = os.path.join("backend", "tests", "test_apks_stage11", "trojan_banker.apk")
        self.cricfy_apk = os.path.join("backend", "tests", "test_apks_three", "cricfy_v4.2.apk")

    def test_01_signing_block_v1_janus(self):
        """Verifies low-level binary parsing identifies V1-only JAR signing (Janus risk)."""
        res = parse_apk_signing_block(self.v1_only_apk)
        self.assertTrue(res["is_v1_jar_signed"])
        self.assertFalse(res["is_v2_signed"])
        self.assertTrue(res["is_janus_vulnerable"])
        self.assertIn("V1", str(res["schemes"]))
        self.assertEqual(res["security_verdict"], "Vulnerable to Janus (V1-only JAR Signing)")

    def test_02_certificate_trust_level_debug(self):
        """Verifies Android Debug certificate detection per CertificateTrustLevel.kt."""
        debug_cert = {
            "issuer": "CN=Android Debug, O=Android, C=US",
            "subject": "CN=Android Debug, O=Android, C=US"
        }
        res = assess_certificate_trust_level(debug_cert)
        self.assertEqual(res["trust_level"], "Debug")
        self.assertTrue(res["is_suspicious"])
        self.assertEqual(res["severity"], "High")

    def test_03_certificate_trust_level_valid(self):
        """Verifies production release certificate is recognized as Valid."""
        prod_cert = {
            "issuer": "CN=Google Inc, O=Alphabet, C=US",
            "subject": "CN=Google Inc, O=Alphabet, C=US"
        }
        res = assess_certificate_trust_level(prod_cert)
        self.assertEqual(res["trust_level"], "Valid")
        self.assertFalse(res["is_suspicious"])
        self.assertEqual(res["severity"], "Clean")

    def test_04_signature_algorithm_assessment(self):
        """Verifies digest assessment per SignatureAlgorithmAssessment.kt."""
        self.assertEqual(assess_signature_algorithm("MD5withRSA")["assessment"], "WeakMd5Digest")
        self.assertTrue(assess_signature_algorithm("MD5withRSA")["is_weak"])

        self.assertEqual(assess_signature_algorithm("SHA1withRSA")["assessment"], "WeakSha1Digest")
        self.assertTrue(assess_signature_algorithm("SHA1withRSA")["is_weak"])

        self.assertEqual(assess_signature_algorithm("SHA256withRSA")["assessment"], "ModernDigest")
        self.assertFalse(assess_signature_algorithm("SHA256withRSA")["is_weak"])

    def test_05_target_sdk_thresholds(self):
        """Verifies target SDK security deprecation per AppClassificationThresholds.kt."""
        # API 21 evades runtime permissions
        res_old = assess_target_sdk_threshold(21)
        self.assertTrue(res_old["is_outdated"])
        self.assertEqual(res_old["severity"], "High")
        self.assertTrue(any("Runtime Permission" in issue for issue in res_old["issues"]))

        # Modern target SDK (API 34)
        res_modern = assess_target_sdk_threshold(34)
        self.assertFalse(res_modern["is_outdated"])
        self.assertEqual(res_modern["severity"], "Clean")

    def test_06_clean_apk_zero_false_positives(self):
        """
        User Requirement:
        'if its clean no need to do anything just show it clean'
        Ensures clean APK evaluates strictly to CLEAN with 0 malicious activities.
        """
        static_data = extract_static_features(self.clean_apk)
        res = test_apk_security_suite(self.clean_apk, static_data)

        self.assertTrue(res["is_clean"], "Clean APK must have is_clean=True")
        self.assertEqual(res["verdict"], "CLEAN")
        self.assertEqual(len(res["malicious_activities"]), 0)
        self.assertEqual(res["failed_tests_count"], 0)
        self.assertEqual(res["status_badge"], "Clean")

    def test_07_trojan_banker_malicious_detection(self):
        """
        User Requirement:
        'after testing the apk file provide me any malicious activity or suspicious activity'
        Verifies Banking Trojan pattern detection.
        """
        static_data = extract_static_features(self.malicious_apk)
        res = test_apk_security_suite(self.malicious_apk, static_data)

        self.assertFalse(res["is_clean"])
        self.assertIn("MALICIOUS", res["verdict"])
        self.assertGreaterEqual(len(res["malicious_activities"]), 1)
        self.assertTrue(any("Banking Trojan" in act for act in res["malicious_activities"]))

    def test_08_cricfy_redirect_detection(self):
        """Verifies phishing redirect detection on real sample."""
        static_data = extract_static_features(self.cricfy_apk)
        res = test_apk_security_suite(
            self.cricfy_apk,
            static_data,
            {"classification": "PHISHING / SUSPICIOUS REDIRECT"}
        )

        self.assertFalse(res["is_clean"])
        self.assertTrue(any("Redirection" in act for act in res["malicious_activities"]))


if __name__ == "__main__":
    unittest.main()
