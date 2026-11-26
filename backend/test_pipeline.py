import sys, os, zipfile, time
sys.path.insert(0, r"c:\Users\USER\APK Analyzer")
from backend.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

test_apk = "test_sample.apk"
with zipfile.ZipFile(test_apk, "w") as z:
    z.writestr("AndroidManifest.xml", b'<manifest package="com.test.sample"></manifest>')
    dex_content = b"android.permission.INTERNET\x00android.permission.SEND_SMS\x00Landroid/telephony/SmsManager;->sendTextMessage"
    z.writestr("classes.dex", dex_content)

print("Uploading test APK...")
with open(test_apk, "rb") as f:
    upload_res = client.post("/api/upload", files={"file": ("test_sample.apk", f, "application/vnd.android.package-archive")})

print("Upload status:", upload_res.status_code)
upload_data = upload_res.json()
print("Upload response:", upload_data)
job_id = upload_data["job_id"]

print("Starting passive analysis...")
pass_res = client.post("/api/passive/analyze", json={"job_id": job_id})
print("Passive analyze status:", pass_res.status_code)

for i in range(15):
    time.sleep(0.5)
    job_status = client.get(f"/api/jobs/{job_id}").json()
    print(f"Poll {i+1}: status={job_status['status']}, progress={job_status['progress']}%")
    if job_status["status"] in ["COMPLETED", "FAILED"]:
        break

res = client.get(f"/api/results/{job_id}").json()
print("\nFinal Result:")
print("Classification:", res.get("classification"))
print("Malware Family:", res.get("malware_family"))
print("Confidence Score:", res.get("confidence_score"))
print("Top SHAP Features:", [f["name"] for f in res.get("shap_explanation", {}).get("top_features", [])[:5]])

# Test STIX Export
stix_res = client.get(f"/api/results/{job_id}/stix")
print("\nSTIX Status:", stix_res.status_code)
stix_data = stix_res.json()
print("STIX Bundle Objects Count:", len(stix_data.get("objects", [])))

if os.path.exists(test_apk):
    os.remove(test_apk)
