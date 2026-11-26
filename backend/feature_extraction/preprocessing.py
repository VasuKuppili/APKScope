import os
import json
import numpy as np
from typing import Dict, Any, List

def load_feature_schema() -> List[str]:
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "models",
        "feature_names.json"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)

def build_feature_vector(static_data: Dict[str, Any], dynamic_data: Dict[str, Any] = None) -> np.ndarray:
    feature_names = load_feature_schema()
    vector = np.zeros((1, len(feature_names)), dtype=np.float32)

    permissions = set(static_data.get("permissions", []))
    api_matches = set(static_data.get("sensitive_api_matches", []))
    dynamic_data = dynamic_data or {}

    for i, feature_name in enumerate(feature_names):
        # 1. Permission flags
        if feature_name.startswith("android.permission."):
            if feature_name in permissions:
                vector[0, i] = 1.0

        # 2. Sensitive API calls
        elif feature_name.startswith("L") and "->" in feature_name:
            # Check if short signature appears in api matches
            matched = any(pattern.lower() in feature_name.lower() for pattern in api_matches)
            if matched:
                vector[0, i] = 1.0

        # 3. Manifest metadata counts
        elif feature_name == "meta_activity_count":
            vector[0, i] = float(static_data.get("activity_count", 0))
        elif feature_name == "meta_service_count":
            vector[0, i] = float(static_data.get("service_count", 0))
        elif feature_name == "meta_receiver_count":
            vector[0, i] = float(static_data.get("receiver_count", 0))
        elif feature_name == "meta_provider_count":
            vector[0, i] = float(static_data.get("provider_count", 0))
        elif feature_name == "meta_intent_filter_count":
            vector[0, i] = float(static_data.get("activity_count", 0) + static_data.get("service_count", 0))

        # 4. Dynamic behavioral features
        elif feature_name.startswith("dyn_"):
            vector[0, i] = float(dynamic_data.get(feature_name, 0.0))

    return vector
