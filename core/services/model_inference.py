import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import joblib
import numpy as np
import onnxruntime as ort
import pandas as pd
from django.conf import settings
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer  # noqa: F401 - needed for joblib
from sklearn.preprocessing import StandardScaler  # noqa: F401 - needed for joblib

ML_MODEL_DIR = Path(settings.BASE_DIR) / "Ml_Model"
TEMPERATURE = 0.25


def _asset_path(filename: str) -> Path:
    path = ML_MODEL_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Missing model asset: {path}")
    return path


@lru_cache(maxsize=1)
def _get_vectorizer():
    return joblib.load(_asset_path("vectorizer_merged.joblib"))


@lru_cache(maxsize=1)
def _get_scaler():
    return joblib.load(_asset_path("scaler.joblib"))


@lru_cache(maxsize=1)
def _get_top_tlds():
    with _asset_path("top_tlds.json").open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("top_tlds.json must contain a list of strings")
    return data


@lru_cache(maxsize=1)
def _get_session():
    session = ort.InferenceSession(str(_asset_path("model.onnx")), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    output_names = [item.name for item in session.get_outputs()]
    return session, input_name, output_names


def _clean_url(url: str) -> str:
    if url is None:
        return ""
    url = str(url).strip().lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\\.", "", url)
    return url.rstrip("/")


def _build_feature_matrix(urls: List[str]):
    vectorizer = _get_vectorizer()
    scaler = _get_scaler()
    top_tlds = _get_top_tlds()

    data = pd.DataFrame({"original_url": urls})
    data["clean_url"] = data["original_url"].astype(str).apply(_clean_url)

    ip_pattern = re.compile(r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])")

    def having_ip_address(value: str) -> bool:
        if value is None:
            return False
        return bool(ip_pattern.search(value))

    def safe_urlparse(raw_url: str):
        if raw_url is None:
            return None
        text = str(raw_url).strip()
        if not text:
            return None
        stripped = re.sub(r"^[a-zA-Z]+://", "", text)
        stripped = re.sub(r"^//", "", stripped)
        if having_ip_address(stripped):
            host = stripped.split("/")[0].split("?")[0].strip()
            class FakeParse:
                def __init__(self, netloc: str, path: str):
                    self.netloc = netloc
                    self.path = path
            return FakeParse(host, "")
        try:
            return urlparse("http://" + stripped)
        except Exception:
            stripped = stripped.replace("[", "").replace("]", "")
            try:
                return urlparse("http://" + stripped)
            except Exception:
                host = stripped.split("/")[0].split("?")[0].strip()
                if not host:
                    return None
                class FakeParseFallback:
                    def __init__(self, netloc: str, path: str):
                        self.netloc = netloc
                        self.path = path
                return FakeParseFallback(host, "")

    def extract_url_features(raw_url: str) -> Dict[str, int]:
        parsed = safe_urlparse(raw_url)
        raw_text = "" if raw_url is None else str(raw_url)
        if parsed is None:
            domain = ""
            path = ""
        else:
            domain = parsed.netloc.split("@")[-1].split(":")[0] if parsed.netloc else ""
            path = parsed.path or ""
        tld = domain.split(".")[-1] if ("." in domain) else ""
        return {
            "domain_len": len(domain),
            "path_len": len(path),
            "num_dots": domain.count(".") + path.count("."),
            "num_digits": sum(ch.isdigit() for ch in raw_text),
            "num_special": sum(1 for ch in raw_text if not ch.isalnum() and ch not in [".", "/", ":", "-", "_"]),
            "has_at": int("@" in raw_text),
            "has_dash": int("-" in raw_text),
            "has_ip": int(having_ip_address(raw_text)),
            "tld": tld,
        }

    feature_frame = pd.DataFrame([extract_url_features(url) for url in data["clean_url"]])
    feature_frame["tld"] = feature_frame["tld"].apply(lambda value: value if value in top_tlds else "other")

    for tld in top_tlds + ["other"]:
        feature_frame[f"tld_{tld}"] = (feature_frame["tld"] == tld).astype(int)
    feature_frame.drop(columns=["tld"], inplace=True)

    num_columns = [
        "domain_len",
        "path_len",
        "num_dots",
        "num_digits",
        "num_special",
        "has_at",
        "has_dash",
        "has_ip",
    ]

    numeric_scaled = scaler.transform(feature_frame[num_columns])
    numeric_sparse = sparse.csr_matrix(numeric_scaled)
    ohe_columns = [col for col in feature_frame.columns if col not in num_columns]
    ohe_sparse = sparse.csr_matrix(feature_frame[ohe_columns].values)
    structural_sparse = sparse.hstack([numeric_sparse, ohe_sparse], format="csr")

    url_hash_features = vectorizer.transform(data["clean_url"])
    final_matrix = sparse.hstack([url_hash_features, structural_sparse], format="csr")
    return final_matrix, data


def _temperature_scaled_sigmoid(margins: np.ndarray) -> np.ndarray:
    return 1 / (1 + np.exp(-margins / TEMPERATURE))


def predict_urls(urls: List[str]) -> List[Dict[str, object]]:
    if not urls:
        return []

    matrix, feature_data = _build_feature_matrix(urls)
    session, input_name, output_names = _get_session()
    matrix = matrix.astype(np.float32).toarray()

    outputs = session.run(output_names, {input_name: matrix})
    labels = outputs[0]
    margins = outputs[1]
    unsafe_probabilities = _temperature_scaled_sigmoid(margins)

    def risk_level(probability: float) -> str:
        if probability < 0.10:
            return "very_safe"
        if probability < 0.33:
            return "low_risk"
        if probability < 0.66:
            return "medium_risk"
        if probability < 0.90:
            return "high_risk"
        return "very_high_risk"

    results: List[Dict[str, object]] = []
    for original_url, prob, label in zip(
        feature_data["original_url"],
        unsafe_probabilities,
        labels,
    ):
        prob_array = np.asarray(prob).flatten()
        unsafe_score = float(prob_array[1] if prob_array.size > 1 else prob_array[0])
        label_array = np.asarray(label).flatten()
        label_value = int(label_array[0])
        results.append(
            {
                "url": str(original_url),
                "label": label_value,
                "probability_unsafe": unsafe_score,
                "risk_level": risk_level(unsafe_score),
            }
        )
    return results
