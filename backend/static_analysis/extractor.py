import os
import zipfile
import re
from typing import Dict, List, Any, Set
import logging
from backend.services.hash_service import calculate_sha256

logger = logging.getLogger("static_extractor")

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_PHONE_STATE": "Allows access to device identifiers (IMEI, IMSI, serial number)",
    "android.permission.SEND_SMS": "Allows application to send SMS messages silently (premium SMS fraud)",
    "android.permission.RECEIVE_SMS": "Allows application to intercept incoming SMS (2FA bypass)",
    "android.permission.READ_SMS": "Allows application to read stored SMS text messages",
    "android.permission.WRITE_SMS": "Allows application to modify or delete SMS messages",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Allows application to automatically execute at device startup",
    "android.permission.ACCESS_FINE_LOCATION": "Allows tracking precise GPS location coordinates",
    "android.permission.ACCESS_COARSE_LOCATION": "Allows tracking approximate cellular/network location",
    "android.permission.CAMERA": "Allows unauthorized photos and video recording",
    "android.permission.RECORD_AUDIO": "Allows unauthorized microphone recording (audio surveillance)",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Allows arbitrary file modifications, deletion, and ransomware encryption",
    "android.permission.READ_EXTERNAL_STORAGE": "Allows reading private user documents, photos, and files",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows drawing overlay windows over other applications (banking phishing)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Allows observing user actions, keystroke logging, and automated clicks",
    "android.permission.BIND_DEVICE_ADMIN": "Grants device administrator control for screen locking and wipe attacks",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Allows downloading and installing secondary APK payloads (dropper)",
    "android.permission.CALL_PHONE": "Allows initiating phone calls without user intervention",
    "android.permission.READ_CONTACTS": "Allows harvesting user contact address book",
    "android.permission.WRITE_CONTACTS": "Allows altering or injecting address book contacts",
    "android.permission.READ_CALL_LOG": "Allows harvesting incoming/outgoing telephone call history",
    "android.permission.WRITE_CALL_LOG": "Allows deleting or modifying telephone call logs",
    "android.permission.INSTALL_PACKAGES": "Privileged permission to install applications directly"
}

SENSITIVE_API_PATTERNS = {
    "sendTextMessage": "Landroid/telephony/SmsManager;->sendTextMessage",
    "getDeviceId": "Landroid/telephony/TelephonyManager;->getDeviceId",
    "getSubscriberId": "Landroid/telephony/TelephonyManager;->getSubscriberId",
    "getSimSerialNumber": "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
    "DexClassLoader": "Ldalvik/system/DexClassLoader;-><init>",
    "PathClassLoader": "Ldalvik/system/PathClassLoader;-><init>",
    "InMemoryDexClassLoader": "Ldalvik/system/InMemoryDexClassLoader;-><init>",
    "getRuntime": "Ljava/lang/Runtime;->getRuntime",
    "Cipher": "Ljavax/crypto/Cipher;->getInstance",
    "HttpURLConnection": "Ljava/net/HttpURLConnection;->connect",
    "DevicePolicyManager": "Landroid/app/admin/DevicePolicyManager;->lockNow",
    "getInstalledPackages": "Landroid/content/pm/PackageManager;->getInstalledPackages",
    "getLastKnownLocation": "Landroid/location/LocationManager;->getLastKnownLocation",
    "requestLocationUpdates": "Landroid/location/LocationManager;->requestLocationUpdates",
    "ACTION_VIEW": "android.intent.action.VIEW",
    "CustomTabsIntent": "androidx/browser/customtabs/CustomTabsIntent",
    "WebView_loadUrl": "Landroid/webkit/WebView;->loadUrl",
    "ANDROID_ID": "android_id",
    "Class_forName": "Ljava/lang/Class;->forName"
}

KNOWN_THIRD_PARTY_SDKS = {
    "com.google.android.gms.ads": "Google Mobile Ads (AdMob)",
    "com.facebook.ads": "Facebook Audience Network",
    "com.unity3d.ads": "Unity Ads",
    "com.applovin": "AppLovin SDK",
    "com.ironsource": "ironSource Ad SDK",
    "com.mbridge.msdk": "Mintegral Ad SDK",
    "com.vungle": "Vungle Liftoff SDK",
    "com.adjust.sdk": "Adjust Attribution SDK",
    "com.appsflyer": "AppsFlyer Analytics",
    "com.google.firebase.analytics": "Firebase Analytics",
    "io.branch.referral": "Branch.io Deep Linking SDK",
    "com.kwad.sdk": "Kwai Ad SDK",
    "com.bytedance.sdk": "Pangle / ByteDance Ad SDK"
}

URL_REGEX = re.compile(rb'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?::[0-9]+)?(?:/[a-zA-Z0-9_\-\.\?\=\&\%#]*)?')
IP_REGEX = re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')

def extract_static_features(apk_path: str) -> Dict[str, Any]:
    """
    Extracts real static application features, manifest metadata, component declarations,
    dangerous permissions, and sensitive DEX API invocations from an APK.
    """
    file_hash = calculate_sha256(apk_path) if os.path.exists(apk_path) else ""
    permissions: List[str] = []
    activities: List[str] = []
    services: List[str] = []
    receivers: List[str] = []
    providers: List[str] = []
    package_name = "com.unknown.app"
    app_name = "Android Application"
    version_name = "1.0"
    version_code = "1"
    min_sdk = "21"
    target_sdk = "33"
    main_activity = "None"
    api_call_matches: Set[str] = set()
    native_libraries: List[str] = []
    certificates: List[str] = []
    androguard_success = False
    embedded_urls: Set[str] = set()
    embedded_domains: Set[str] = set()
    embedded_ips: Set[str] = set()
    detected_sdks: Set[str] = set()
    redirect_indicators: List[str] = []
    privacy_sensitive_apis: List[str] = []

    # 1. Attempt extraction with Androguard
    try:
        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        a = APK(apk_path)
        if a.is_valid_APK():
            package_name = a.get_package() or package_name
            app_name = a.get_app_name() or app_name
            version_name = str(a.get_androidversion_name() or version_name)
            version_code = str(a.get_androidversion_code() or version_code)
            min_sdk = str(a.get_min_sdk_version() or min_sdk)
            target_sdk = str(a.get_target_sdk_version() or target_sdk)
            main_activity = str(a.get_main_activity() or main_activity)

            permissions = list(a.get_permissions() or [])
            activities = list(a.get_activities() or [])
            services = list(a.get_services() or [])
            receivers = list(a.get_receivers() or [])
            providers = list(a.get_providers() or [])
            native_libraries = list(a.get_libraries() or [])

            # Inspect DEX code strings and method references
            for dex_bytes in a.get_all_dex():
                try:
                    d = DEX(dex_bytes)
                    for string_val in d.get_strings():
                        for pattern, canonical_name in SENSITIVE_API_PATTERNS.items():
                            if pattern in string_val:
                                api_call_matches.add(pattern)
                                api_call_matches.add(canonical_name)
                except Exception:
                    continue

            androguard_success = True
    except Exception as e:
        logger.warning(f"Androguard extraction encountered fallback: {e}")

    # 2. Raw Archive Inspection (Fallback or supplemental deep scan)
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            file_list = z.namelist()

            # Find native libraries in lib/
            for name in file_list:
                if name.startswith("lib/") and name.endswith(".so"):
                    lib_name = os.path.basename(name)
                    if lib_name not in native_libraries:
                        native_libraries.append(lib_name)
                elif name.startswith("META-INF/") and (name.endswith(".RSA") or name.endswith(".DSA") or name.endswith(".EC")):
                    certificates.append(os.path.basename(name))

            # Scan classes*.dex bytes for strings and patterns
            dex_files = [n for n in file_list if n.startswith("classes") and n.endswith(".dex")]
            for dex_file in dex_files:
                try:
                    dex_data = z.read(dex_file)

                    # Extract android.permission strings if manifest parsing yielded no declared permissions (e.g. fallback or mock APK)
                    if len(permissions) == 0:
                        perm_matches = re.findall(rb"android\.permission\.[A-Za-z0-9_]+", dex_data)
                        for p in perm_matches:
                            decoded_p = p.decode("utf-8", errors="ignore")
                            if decoded_p not in permissions:
                                permissions.append(decoded_p)

                    # Check sensitive API call tokens
                    for pattern, canonical in SENSITIVE_API_PATTERNS.items():
                        if pattern.encode("utf-8") in dex_data:
                            api_call_matches.add(pattern)
                            api_call_matches.add(canonical)

                    # Extract URLs and domains embedded in DEX bytecode
                    raw_urls = URL_REGEX.findall(dex_data)
                    for u in raw_urls[:100]:
                        u_str = u.decode("utf-8", errors="ignore").strip(".,;\"'()[]{}")
                        if len(u_str) > 10 and not u_str.endswith(".png") and not u_str.endswith(".xml"):
                            embedded_urls.add(u_str)
                            try:
                                from urllib.parse import urlparse
                                domain = urlparse(u_str).netloc.split(":")[0]
                                if domain and "." in domain and not domain.endswith(".android.com") and not domain.endswith(".w3.org"):
                                    embedded_domains.add(domain)
                            except Exception:
                                pass

                    # Extract embedded IP addresses
                    raw_ips = IP_REGEX.findall(dex_data)
                    for ip in raw_ips[:40]:
                        ip_str = ip.decode("utf-8", errors="ignore")
                        if not ip_str.startswith("0.") and not ip_str.startswith("127."):
                            embedded_ips.add(ip_str)

                    # Detect third-party SDKs
                    for sdk_prefix, sdk_name in KNOWN_THIRD_PARTY_SDKS.items():
                        if sdk_prefix.encode("utf-8") in dex_data:
                            detected_sdks.add(sdk_name)
                except Exception as dex_err:
                    logger.debug(f"Error scanning dex file {dex_file}: {dex_err}")

            # Fallback manifest extraction if Androguard failed
            if not androguard_success and "AndroidManifest.xml" in file_list:
                manifest_data = z.read("AndroidManifest.xml")
                # Look for package name pattern
                pkg_match = re.search(rb'package="([a-zA-Z0-9_\.]+)"', manifest_data)
                if pkg_match:
                    package_name = pkg_match.group(1).decode("utf-8", errors="ignore")
                
                # Check for activities and services regex
                activity_matches = re.findall(rb'activity[^>]*android:name="([a-zA-Z0-9_\.]+)"', manifest_data)
                for act in activity_matches:
                    activities.append(act.decode("utf-8", errors="ignore"))

                service_matches = re.findall(rb'service[^>]*android:name="([a-zA-Z0-9_\.]+)"', manifest_data)
                for srv in service_matches:
                    services.append(srv.decode("utf-8", errors="ignore"))

    except Exception as archive_err:
        logger.error(f"Archive inspection error: {archive_err}")

    # Remove duplicates
    permissions = sorted(list(set(permissions)))
    activities = sorted(list(set(activities)))
    services = sorted(list(set(services)))
    receivers = sorted(list(set(receivers)))
    providers = sorted(list(set(providers)))

    # Identify dangerous permissions and reasons
    dangerous_details = []
    dangerous_found = []
    for p in permissions:
        if p in DANGEROUS_PERMISSIONS:
            dangerous_found.append(p)
            dangerous_details.append({
                "permission": p,
                "risk_description": DANGEROUS_PERMISSIONS[p]
            })

    total_components = len(activities) + len(services) + len(receivers) + len(providers)
    intent_filter_count = max(len(activities) + len(services), 1)

    # Evaluate redirect and browser-launching indicators
    if any(k in api_call_matches for k in ["ACTION_VIEW", "CustomTabsIntent", "WebView_loadUrl"]):
        redirect_indicators.append("External browser launching / URL redirect capability (android.intent.action.VIEW, CustomTabs, WebView.loadUrl)")

    # Evaluate personal / sensitive data access capabilities
    privacy_candidates = [
        ("getDeviceId", "Device IMEI / Unique Hardware Identifier access"),
        ("ANDROID_ID", "Android Secure Device Identifier access"),
        ("getSubscriberId", "IMSI Subscriber Identifier access"),
        ("getSimSerialNumber", "SIM Card Serial Number access"),
        ("getLastKnownLocation", "GPS / Geographic location access"),
        ("requestLocationUpdates", "Continuous location tracking hook"),
        ("getInstalledPackages", "Installed application inventory query"),
    ]
    for key, desc in privacy_candidates:
        if key in api_call_matches:
            privacy_sensitive_apis.append(desc)

    return {
        "file_hash": file_hash,
        "package_name": package_name,
        "app_name": app_name,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "main_activity": main_activity,
        "permissions": permissions,
        "dangerous_permissions": dangerous_found,
        "dangerous_details": dangerous_details,
        "permission_count": len(permissions),
        "activities": activities,
        "activity_count": len(activities),
        "services": services,
        "service_count": len(services),
        "receivers": receivers,
        "receiver_count": len(receivers),
        "providers": providers,
        "provider_count": len(providers),
        "total_components": total_components,
        "intent_filter_count": intent_filter_count,
        "sensitive_api_matches": sorted(list(api_call_matches)),
        "native_libraries": native_libraries,
        "has_native_code": len(native_libraries) > 0,
        "certificates": certificates,
        "embedded_urls": sorted(list(embedded_urls))[:60],
        "embedded_domains": sorted(list(embedded_domains))[:40],
        "embedded_ips": sorted(list(embedded_ips))[:20],
        "third_party_sdks": sorted(list(detected_sdks)),
        "redirect_indicators": redirect_indicators,
        "privacy_sensitive_apis": privacy_sensitive_apis
    }
