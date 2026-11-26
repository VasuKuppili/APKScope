import os
import sys
import unittest
import numpy as np

# Ensure repository root is on Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.classification.predictor import predict_malware_family, ModelLoader
from backend.explainable_ai.shap_explainer import explain_prediction, ShapExplainerManager
from backend.feature_extraction.preprocessing import build_feature_vector

class TestExplainableAIAndMultiClassInference(unittest.TestCase):

    def test_01_model_and_classes_loaded(self):
        """FR-06: Model and multi-class label encoder must be properly initialized"""
        clf, le = ModelLoader.get_models()
        self.assertIsNotNone(clf)
        self.assertIsNotNone(le)
        expected_classes = {"Benign", "Trojan.Banker", "Ransomware", "Adware", "Spyware", "Dropper"}
        self.assertTrue(set(le.classes_).issuperset(expected_classes))

    def test_02_shap_explainer_initialization(self):
        """FR-07: TreeExplainer and 69-feature vector metadata must load correctly"""
        explainer, feature_names = ShapExplainerManager.get_explainer()
        self.assertIsNotNone(explainer)
        self.assertIsInstance(feature_names, list)
        self.assertEqual(len(feature_names), 69)

    def test_03_ransomware_xai_attribution(self):
        """FR-06 / FR-07: Verify Ransomware features drive high SHAP importance and correct categorization"""
        clf, le = ModelLoader.get_models()
        ransomware_idx = int(list(le.classes_).index("Ransomware"))

        static_data = {
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            "sensitive_api_matches": [
                "Ljavax/crypto/Cipher;->getInstance",
                "Ljavax/crypto/Cipher;->doFinal",
                "Landroid/app/admin/DevicePolicyManager;->lockNow",
                "Ljava/io/File;->delete"
            ],
            "activity_count": 2,
            "service_count": 2,
            "receiver_count": 1,
            "provider_count": 0,
            "intent_filter_count": 3
        }
        dynamic_data = {
            "dyn_network_http_count": 5.0,
            "dyn_network_dns_queries": 2.0,
            "dyn_network_raw_sockets": 0.0,
            "dyn_file_encryption_ops": 120.0,
            "dyn_file_delete_ops": 35.0,
            "dyn_su_root_attempts": 0.0,
            "dyn_process_exec_calls": 2.0,
            "dyn_sms_intercept_attempts": 0.0,
            "dyn_screen_overlay_events": 1.0
        }

        vec = build_feature_vector(static_data, dynamic_data)
        pred = predict_malware_family(vec)
        self.assertEqual(pred["classification"], "Malicious")
        self.assertEqual(pred["malware_family"], "Ransomware")
        self.assertGreaterEqual(pred["confidence_score"], 70.0)

        shap_result = explain_prediction(vec, ransomware_idx)
        self.assertIn("top_features", shap_result)
        self.assertIn("category_breakdown", shap_result)

        # Verify top features contain encryption / device admin features
        top_feature_names = [f["name"] for f in shap_result["top_features"]]
        has_crypto_feature = any(
            "Cipher" in name or "encryption" in name or "DevicePolicy" in name or "BIND_DEVICE_ADMIN" in name
            for name in top_feature_names
        )
        self.assertTrue(has_crypto_feature, f"Expected cryptographic/device indicators in top SHAP features: {top_feature_names}")

        # Verify category breakdown percentages sum to ~100%
        cat_pct_sum = sum(c["percentage"] for c in shap_result["category_breakdown"])
        self.assertAlmostEqual(cat_pct_sum, 100.0, delta=2.0)

    def test_04_trojan_banker_xai_attribution(self):
        """FR-06 / FR-07: Verify Trojan.Banker features drive high SHAP importance and correct categorization"""
        clf, le = ModelLoader.get_models()
        banker_idx = int(list(le.classes_).index("Trojan.Banker"))

        static_data = {
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW"
            ],
            "sensitive_api_matches": [
                "Landroid/telephony/SmsManager;->sendTextMessage",
                "Ldalvik/system/DexClassLoader;-><init>"
            ],
            "activity_count": 3,
            "service_count": 3,
            "receiver_count": 2,
            "provider_count": 0,
            "intent_filter_count": 4
        }
        dynamic_data = {
            "dyn_network_http_count": 18.0,
            "dyn_network_dns_queries": 8.0,
            "dyn_network_raw_sockets": 1.0,
            "dyn_file_encryption_ops": 0.0,
            "dyn_file_delete_ops": 0.0,
            "dyn_su_root_attempts": 0.0,
            "dyn_process_exec_calls": 3.0,
            "dyn_sms_intercept_attempts": 10.0,
            "dyn_screen_overlay_events": 8.0
        }

        vec = build_feature_vector(static_data, dynamic_data)
        pred = predict_malware_family(vec)
        self.assertEqual(pred["classification"], "Malicious")
        self.assertEqual(pred["malware_family"], "Trojan.Banker")

        shap_result = explain_prediction(vec, banker_idx)
        top_feature_names = [f["name"] for f in shap_result["top_features"]]
        has_banker_signal = any(
            "sms" in name.lower() or "SYSTEM_ALERT_WINDOW" in name or "overlay" in name or "sendTextMessage" in name
            for name in top_feature_names
        )
        self.assertTrue(has_banker_signal, f"Expected SMS/Overlay indicators in top SHAP features: {top_feature_names}")

    def test_05_spyware_xai_attribution(self):
        """FR-06 / FR-07: Verify Spyware features drive surveillance indicators in SHAP"""
        clf, le = ModelLoader.get_models()
        spyware_idx = int(list(le.classes_).index("Spyware"))

        static_data = {
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION"
            ],
            "sensitive_api_matches": [
                "Landroid/location/LocationManager;->getLastKnownLocation",
                "Landroid/telephony/TelephonyManager;->getDeviceId"
            ],
            "activity_count": 2,
            "service_count": 3,
            "receiver_count": 1,
            "provider_count": 0,
            "intent_filter_count": 3
        }
        dynamic_data = {
            "dyn_network_http_count": 30.0,
            "dyn_network_dns_queries": 15.0,
            "dyn_network_raw_sockets": 0.0,
            "dyn_file_encryption_ops": 0.0,
            "dyn_file_delete_ops": 0.0,
            "dyn_su_root_attempts": 0.0,
            "dyn_process_exec_calls": 1.0,
            "dyn_sms_intercept_attempts": 0.0,
            "dyn_screen_overlay_events": 0.0
        }

        vec = build_feature_vector(static_data, dynamic_data)
        pred = predict_malware_family(vec)
        self.assertEqual(pred["classification"], "Malicious")
        self.assertEqual(pred["malware_family"], "Spyware")

        shap_result = explain_prediction(vec, spyware_idx)
        top_feature_names = [f["name"] for f in shap_result["top_features"]]
        has_spyware_signal = any(
            "RECORD_AUDIO" in name or "CAMERA" in name or "CONTACTS" in name or "LOCATION" in name
            for name in top_feature_names
        )
        self.assertTrue(has_spyware_signal, f"Expected surveillance indicators in top SHAP features: {top_feature_names}")

    def test_06_benign_attribution_no_malicious_bias(self):
        """FR-06 / FR-07: Verify Benign application produces safe classification without false positive alarm"""
        clf, le = ModelLoader.get_models()
        benign_idx = int(list(le.classes_).index("Benign"))

        static_data = {
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE"
            ],
            "sensitive_api_matches": [],
            "activity_count": 4,
            "service_count": 0,
            "receiver_count": 0,
            "provider_count": 0,
            "intent_filter_count": 2
        }
        dynamic_data = {
            "dyn_network_http_count": 1.0,
            "dyn_network_dns_queries": 1.0,
            "dyn_network_raw_sockets": 0.0,
            "dyn_file_encryption_ops": 0.0,
            "dyn_file_delete_ops": 0.0,
            "dyn_su_root_attempts": 0.0,
            "dyn_process_exec_calls": 0.0,
            "dyn_sms_intercept_attempts": 0.0,
            "dyn_screen_overlay_events": 0.0
        }

        vec = build_feature_vector(static_data, dynamic_data)
        pred = predict_malware_family(vec)
        self.assertEqual(pred["classification"], "Benign")
        self.assertEqual(pred["malware_family"], "None")

        shap_result = explain_prediction(vec, benign_idx)
        self.assertGreater(len(shap_result["top_features"]), 0)
        self.assertIn("base_value", shap_result)

if __name__ == "__main__":
    unittest.main()
