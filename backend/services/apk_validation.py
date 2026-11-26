import os
import zipfile

MAX_FILE_SIZE = int(os.getenv("MAX_UPLOAD_SIZE_MB", 100)) * 1024 * 1024

class APKValidationError(Exception):
    pass

def validate_apk_file(filepath: str, original_filename: str) -> dict:
    if not original_filename.lower().endswith(".apk"):
        raise APKValidationError(f"Invalid file extension. Expected an Android APK package (.apk), received: {original_filename}")

    file_size = os.path.getsize(filepath)
    if file_size == 0:
        raise APKValidationError("The uploaded APK file is empty (0 bytes).")

    if file_size > MAX_FILE_SIZE:
        max_mb = MAX_FILE_SIZE // (1024 * 1024)
        actual_mb = round(file_size / (1024 * 1024), 2)
        raise APKValidationError(f"File size exceeds limit of {max_mb} MB (current: {actual_mb} MB).")

    # Check zip magic bytes: PK\x03\x04
    with open(filepath, "rb") as f:
        magic = f.read(4)
        if magic != b"PK\x03\x04":
            raise APKValidationError("Invalid file header. File is not a valid zip/APK archive.")

    # Validate zip integrity and AndroidManifest.xml presence
    try:
        with zipfile.ZipFile(filepath, "r") as z:
            bad_file = z.testzip()
            if bad_file:
                raise APKValidationError(f"Corrupted archive structure at entry: {bad_file}")
            
            namelist = z.namelist()
            if "AndroidManifest.xml" not in namelist:
                raise APKValidationError("Invalid APK package: missing AndroidManifest.xml.")
            
            has_dex = any(name.endswith(".dex") for name in namelist)
            
            return {
                "valid": True,
                "file_size": file_size,
                "has_manifest": True,
                "has_dex": has_dex,
                "entry_count": len(namelist)
            }
    except zipfile.BadZipFile:
        raise APKValidationError("Corrupted or malformed APK package: cannot be parsed as a zip archive.")
    except Exception as e:
        if isinstance(e, APKValidationError):
            raise
        raise APKValidationError(f"APK validation failed: {str(e)}")
