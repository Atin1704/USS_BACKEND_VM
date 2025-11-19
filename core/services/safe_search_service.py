import json
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

from core.services.model_inference import predict_urls


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = PROJECT_ROOT / "db.sqlite3"


class SafeSearchError(RuntimeError):
    """Raised when the safety lookup fails unexpectedly."""


def _risk_level(probability_unsafe: float) -> str:
    if probability_unsafe < 0.10:
        return "very_safe"
    if probability_unsafe < 0.33:
        return "low_risk"
    if probability_unsafe < 0.66:
        return "medium_risk"
    if probability_unsafe < 0.90:
        return "high_risk"
    return "very_high_risk"


@lru_cache(maxsize=1)
def _validate_database() -> None:
    if not DB_PATH.exists():
        raise SafeSearchError(f"SQLite database not found at {DB_PATH}")


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        raise ValueError("A non-empty URL must be supplied.")
    return value


def _lookup_database(cursor: sqlite3.Cursor, table: str, url: str) -> bool:
    cursor.execute(f"SELECT 1 FROM {table} WHERE url = ? LIMIT 1", (url,))
    return cursor.fetchone() is not None


def score_url(url: str) -> Dict[str, object]:
    """Return the safety assessment for a single URL.

    The lookup follows three stages:
    1. Exact match in the safe_links table → deterministic safe response.
    2. Exact match in the unsafe_links table → deterministic unsafe response.
    3. Otherwise delegate to the ONNX model through predict_urls.
    """

    normalized = _normalize_url(url)
    _validate_database()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if _lookup_database(cursor, "safe_links", normalized):
                probability = 0.0
                return {
                    "url": normalized,
                    "label": 0,
                    "probability_unsafe": probability,
                    "risk_level": _risk_level(probability),
                    "source": "database_safe",
                }

            if _lookup_database(cursor, "unsafe_links", normalized):
                probability = 1.0
                return {
                    "url": normalized,
                    "label": 1,
                    "probability_unsafe": probability,
                    "risk_level": _risk_level(probability),
                    "source": "database_unsafe",
                }
    except Exception as exc:  # pragma: no cover - alignment with script usage
        raise SafeSearchError(str(exc)) from exc

    # Fallback to model inference
    predictions = predict_urls([normalized])
    if not predictions:
        raise SafeSearchError("Model inference returned no results.")

    prediction = predictions[0]
    prediction["source"] = "model"
    return prediction


def score_urls(urls: List[str]) -> Dict[str, List[Dict[str, object]]]:
    """Convenience wrapper for bulk lookups returning the API payload shape."""
    return {"prediction": [score_url(url) for url in urls]}


def main(url: str) -> None:
    """CLI helper to print the JSON response for a single URL."""
    result = score_urls([url])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    raise SystemExit("Run safe_search.py instead of executing this module directly.")
