"""CLI helper to classify URLs using the Safe Search workflow.

Usage::

	python safe_search.py https://example.com

The command prints the JSON payload produced by the Safe Search service.
"""

from __future__ import annotations

import argparse
import os
import sys


def configure_django() -> None:
	os.environ.setdefault("DJANGO_SETTINGS_MODULE", "uss_backend.settings")
	try:
		import django

		django.setup()
	except Exception as exc:  # pragma: no cover - defensive: script entry point
		raise SystemExit(f"Failed to initialise Django environment: {exc}")


def parse_args(argv: list[str]) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Score URL safety using local database + ONNX model")
	parser.add_argument("url", help="URL to classify")
	return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
	configure_django()

	from core.services.safe_search_service import main as score_main

	args = parse_args(argv or sys.argv[1:])
	score_main(args.url)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())