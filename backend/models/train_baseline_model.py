"""
Train Baseline Multi-Class Android Malware Family Classifier
Features:
- Static: Android permissions, sensitive API calls, manifest component counts
- Dynamic: Network operations, file activity, process execution
Output:
- backend/models/malware_classifier.joblib
- backend/models/feature_names.json
- backend/models/label_encoder.joblib
- backend/models/model_metrics.json
"""

import os
import json
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    balanced_accuracy_score,
    matthews_corrcoef,
    classification_report
)

def build_feature_schema():
    permissions = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.WRITE_SMS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.GET_TASKS",
        "android.permission.RESTART_PACKAGES",
        "android.permission.WAKE_LOCK",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.USE_BIOMETRIC",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.FOREGROUND_SERVICE"
    ]

    api_calls = [
        "Landroid/telephony/SmsManager;->sendTextMessage",
        "Landroid/telephony/TelephonyManager;->getDeviceId",
        "Landroid/telephony/TelephonyManager;->getSubscriberId",
        "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
        "Ljava/lang/reflect/Method;->invoke",
        "Ldalvik/system/DexClassLoader;-><init>",
        "Ldalvik/system/PathClassLoader;-><init>",
        "Ljava/lang/Runtime;->getRuntime",
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/ProcessBuilder;->start",
        "Landroid/app/admin/DevicePolicyManager;->lockNow",
        "Landroid/app/admin/DevicePolicyManager;->wipeData",
        "Ljavax/crypto/Cipher;->getInstance",
        "Ljavax/crypto/Cipher;->doFinal",
        "Ljava/net/HttpURLConnection;->connect",
        "Ljava/net/Socket;-><init>",
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Landroid/content/pm/PackageManager;->getInstalledPackages",
        "Landroid/content/ContentResolver;->query",
        "Landroid/content/Intent;->setAction",
        "Landroid/os/Environment;->getExternalStorageDirectory",
        "Ljava/io/File;->delete",
        "Ljava/io/FileOutputStream;->write"
    ]

    metadata_metrics = [
        "meta_activity_count",
        "meta_service_count",
        "meta_receiver_count",
        "meta_provider_count",
        "meta_intent_filter_count"
    ]

    dynamic_features = [
        "dyn_network_http_count",
        "dyn_network_dns_queries",
        "dyn_network_raw_sockets",
        "dyn_file_encryption_ops",
        "dyn_file_delete_ops",
        "dyn_su_root_attempts",
        "dyn_process_exec_calls",
        "dyn_sms_intercept_attempts",
        "dyn_screen_overlay_events"
    ]

    return permissions + api_calls + metadata_metrics + dynamic_features

def generate_synthetic_benchmark(features, n_samples=3000, random_state=42):
    rng = np.random.RandomState(random_state)
    families = ["Benign", "Trojan.Banker", "Ransomware", "Adware", "Spyware", "Dropper"]
    
    n_features = len(features)
    X = np.zeros((n_samples, n_features), dtype=np.float32)
    y = []

    f_map = {name: i for i, name in enumerate(features)}

    for i in range(n_samples):
        # Pick family with realistic distribution
        fam = rng.choice(families, p=[0.40, 0.15, 0.12, 0.13, 0.10, 0.10])
        y.append(fam)

        # Baseline noise
        row = rng.binomial(1, 0.05, size=n_features).astype(np.float32)

        # Base metadata component counts
        row[f_map["meta_activity_count"]] = rng.randint(1, 15)
        row[f_map["meta_service_count"]] = rng.randint(0, 5)
        row[f_map["meta_receiver_count"]] = rng.randint(0, 5)
        row[f_map["meta_provider_count"]] = rng.randint(0, 2)
        row[f_map["meta_intent_filter_count"]] = rng.randint(1, 10)

        # In 50% of samples, simulate passive analysis (dynamic features = 0)
        is_passive_sample = rng.binomial(1, 0.5)

        # Family specific feature footprints
        if fam == "Benign":
            row[f_map["android.permission.INTERNET"]] = rng.binomial(1, 0.65)
            row[f_map["android.permission.ACCESS_NETWORK_STATE"]] = rng.binomial(1, 0.60)
            row[f_map["Ljava/net/HttpURLConnection;->connect"]] = rng.binomial(1, 0.40)
            if not is_passive_sample:
                row[f_map["dyn_network_http_count"]] = rng.randint(0, 8)

        elif fam == "Trojan.Banker":
            row[f_map["android.permission.INTERNET"]] = 1.0
            row[f_map["android.permission.READ_PHONE_STATE"]] = rng.binomial(1, 0.95)
            row[f_map["android.permission.SYSTEM_ALERT_WINDOW"]] = rng.binomial(1, 0.95)
            row[f_map["android.permission.BIND_ACCESSIBILITY_SERVICE"]] = rng.binomial(1, 0.95)
            row[f_map["android.permission.RECEIVE_SMS"]] = rng.binomial(1, 0.90)
            row[f_map["android.permission.READ_SMS"]] = rng.binomial(1, 0.90)
            row[f_map["android.permission.SEND_SMS"]] = rng.binomial(1, 0.90)
            row[f_map["Landroid/telephony/SmsManager;->sendTextMessage"]] = rng.binomial(1, 0.90)
            row[f_map["Ldalvik/system/DexClassLoader;-><init>"]] = rng.binomial(1, 0.85)
            row[f_map["Landroid/telephony/TelephonyManager;->getDeviceId"]] = rng.binomial(1, 0.85)
            if not is_passive_sample:
                row[f_map["dyn_screen_overlay_events"]] = rng.randint(3, 15)
                row[f_map["dyn_sms_intercept_attempts"]] = rng.randint(1, 8)
                row[f_map["dyn_network_http_count"]] = rng.randint(10, 30)

        elif fam == "Ransomware":
            row[f_map["android.permission.WRITE_EXTERNAL_STORAGE"]] = 1.0
            row[f_map["android.permission.READ_EXTERNAL_STORAGE"]] = 1.0
            row[f_map["android.permission.BIND_DEVICE_ADMIN"]] = rng.binomial(1, 0.95)
            row[f_map["android.permission.SYSTEM_ALERT_WINDOW"]] = rng.binomial(1, 0.90)
            row[f_map["Ljavax/crypto/Cipher;->getInstance"]] = rng.binomial(1, 0.95)
            row[f_map["Ljavax/crypto/Cipher;->doFinal"]] = rng.binomial(1, 0.90)
            row[f_map["Landroid/app/admin/DevicePolicyManager;->lockNow"]] = rng.binomial(1, 0.85)
            row[f_map["Ljava/io/File;->delete"]] = rng.binomial(1, 0.85)
            if not is_passive_sample:
                row[f_map["dyn_file_encryption_ops"]] = rng.randint(25, 200)
                row[f_map["dyn_file_delete_ops"]] = rng.randint(10, 80)

        elif fam == "Adware":
            row[f_map["android.permission.INTERNET"]] = 1.0
            row[f_map["android.permission.ACCESS_NETWORK_STATE"]] = 1.0
            row[f_map["android.permission.ACCESS_WIFI_STATE"]] = rng.binomial(1, 0.90)
            row[f_map["android.permission.ACCESS_COARSE_LOCATION"]] = rng.binomial(1, 0.80)
            row[f_map["android.permission.SYSTEM_ALERT_WINDOW"]] = rng.binomial(1, 0.70)
            row[f_map["Landroid/telephony/TelephonyManager;->getDeviceId"]] = rng.binomial(1, 0.85)
            if not is_passive_sample:
                row[f_map["dyn_network_http_count"]] = rng.randint(30, 100)
                row[f_map["dyn_network_dns_queries"]] = rng.randint(20, 50)

        elif fam == "Spyware":
            row[f_map["android.permission.RECORD_AUDIO"]] = rng.binomial(1, 0.95)
            row[f_map["android.permission.CAMERA"]] = rng.binomial(1, 0.90)
            row[f_map["android.permission.ACCESS_FINE_LOCATION"]] = rng.binomial(1, 0.95)
            row[f_map["android.permission.READ_CONTACTS"]] = rng.binomial(1, 0.90)
            row[f_map["android.permission.READ_CALL_LOG"]] = rng.binomial(1, 0.90)
            row[f_map["android.permission.READ_SMS"]] = rng.binomial(1, 0.85)
            row[f_map["Landroid/location/LocationManager;->getLastKnownLocation"]] = rng.binomial(1, 0.90)
            if not is_passive_sample:
                row[f_map["dyn_network_http_count"]] = rng.randint(15, 40)

        elif fam == "Dropper":
            row[f_map["android.permission.REQUEST_INSTALL_PACKAGES"]] = 1.0
            row[f_map["android.permission.WRITE_EXTERNAL_STORAGE"]] = 1.0
            row[f_map["android.permission.INTERNET"]] = 1.0
            row[f_map["Ldalvik/system/DexClassLoader;-><init>"]] = rng.binomial(1, 0.95)
            row[f_map["Ljava/lang/Runtime;->exec"]] = rng.binomial(1, 0.85)
            if not is_passive_sample:
                row[f_map["dyn_process_exec_calls"]] = rng.randint(2, 10)
                row[f_map["dyn_su_root_attempts"]] = rng.binomial(1, 0.40)

        X[i] = row

    return X, np.array(y)

def train_and_save():
    model_dir = os.path.dirname(os.path.abspath(__file__))
    features = build_feature_schema()
    
    print(f"Total features defined: {len(features)}")
    X, y = generate_synthetic_benchmark(features, n_samples=4000)

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    precision = float(precision_score(y_test, y_pred, average="weighted"))
    recall = float(recall_score(y_test, y_pred, average="weighted"))
    f1 = float(f1_score(y_test, y_pred, average="weighted"))
    balanced_acc = float(balanced_accuracy_score(y_test, y_pred))
    mcc = float(matthews_corrcoef(y_test, y_pred))

    metrics = {
        "model_type": "RandomForestClassifier",
        "model_version": "1.0.0",
        "dataset_benchmark": "Drebin / CICInvesAndMal2019 Compatible Schema",
        "num_features": len(features),
        "classes": list(le.classes_),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "balanced_accuracy": round(balanced_acc, 4),
        "matthews_correlation_coefficient": round(mcc, 4)
    }

    print("\n--- MODEL EVALUATION METRICS ---")
    for k, v in metrics.items():
        print(f"{k}: {v}")

    # Save artifacts
    model_path = os.path.join(model_dir, "malware_classifier.joblib")
    features_path = os.path.join(model_dir, "feature_names.json")
    le_path = os.path.join(model_dir, "label_encoder.joblib")
    metrics_path = os.path.join(model_dir, "model_metrics.json")

    joblib.dump(clf, model_path)
    joblib.dump(le, le_path)
    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(features, f, indent=2)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(f"\nSaved model to: {model_path}")
    print(f"Saved feature schema to: {features_path}")
    print(f"Saved label encoder to: {le_path}")
    print(f"Saved metrics to: {metrics_path}")

if __name__ == "__main__":
    train_and_save()
