
"""Populate SQLite tables with safe and unsafe URL datasets.

The script builds two tables, `safe_links` and `unsafe_links`, inside the
existing SQLite database. Domains are extracted from each URL to support fast
lookup patterns, and the top 80k domains are added to the safe table for broader
coverage of common sites.
"""

from __future__ import annotations

import csv
import sqlite3
from itertools import islice
from pathlib import Path
from typing import Iterable, Iterator, Sequence, Tuple
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parents[1]
DB_PATH = ROOT_DIR / "db.sqlite3"
DATA_DIR = ROOT_DIR / "Database"
PHISHTANK_PATH = DATA_DIR / "phishtank.csv"
URLHAUS_PATH = DATA_DIR / "url_haus_malware.csv"
BALANCED_PATH = DATA_DIR / "balanced_urls.csv"
TOP_DOMAINS_PATH = DATA_DIR / "top-1m.csv"
BATCH_SIZE = 10_000

Row = Tuple[str, str]


def extract_domain(url: str) -> str | None:
    """Return the lowercase hostname for a URL or None when parsing fails."""
    candidate = url.strip()
    if not candidate:
        return None

    parsed = urlparse(candidate)
    host = parsed.hostname
    if host:
        return host.lower()

    if "//" not in candidate:
        parsed = urlparse(f"http://{candidate}")
        host = parsed.hostname
        if host:
            return host.lower()

    return None


def configure_connection(conn: sqlite3.Connection) -> None:
    """Set pragmatic options optimized for one-time bulk inserts."""
    conn.execute("PRAGMA journal_mode=OFF;")
    conn.execute("PRAGMA synchronous=OFF;")
    conn.execute("PRAGMA locking_mode=EXCLUSIVE;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA mmap_size=536870912;")  # 512 MiB window
    conn.execute("PRAGMA cache_size=-524288;")   # ~512 MiB cache
    conn.execute("PRAGMA threads=4;")


def create_schema(conn: sqlite3.Connection) -> None:
    """Drop and recreate the link tables with supporting indexes."""
    conn.executescript(
        """
        DROP TABLE IF EXISTS safe_links;
        DROP TABLE IF EXISTS unsafe_links;

        CREATE TABLE safe_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE
        );

        CREATE TABLE unsafe_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE
        );

        CREATE INDEX idx_safe_domain ON safe_links(domain);
        CREATE INDEX idx_safe_domain_url ON safe_links(domain, url);
        CREATE INDEX idx_unsafe_domain ON unsafe_links(domain);
        CREATE INDEX idx_unsafe_domain_url ON unsafe_links(domain, url);
        """
    )


def split_balanced_dataset(path: Path) -> Tuple[Sequence[str], Sequence[str]]:
    """Read the balanced dataset and split it into deterministic halves."""
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        urls = [row["url"].strip() for row in reader if row.get("url", "").strip()]

    midpoint = len(urls) // 2
    return urls[:midpoint], urls[midpoint:]


def iter_phishtank_urls(path: Path) -> Iterator[str]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            url = row.get("url", "").strip()
            if url:
                yield url


def iter_urlhaus_urls(path: Path) -> Iterator[str]:
    fieldnames = [
        "id",
        "dateadded",
        "url",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "urlhaus_link",
        "reporter",
    ]

    with path.open(newline="", encoding="utf-8") as handle:
        filtered_lines = (line for line in handle if line and not line.startswith("#"))
        reader = csv.DictReader(filtered_lines, fieldnames=fieldnames)
        for row in reader:
            url = row.get("url", "").strip()
            if url:
                yield url


def iter_top_domains(path: Path, limit: int = 150000) -> Iterator[str]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for _, domain in islice(reader, limit):
            domain = domain.strip()
            if domain:
                yield f"https://{domain}/"


def to_rows(urls: Iterable[str]) -> Iterator[Row]:
    for url in urls:
        domain = extract_domain(url)
        if domain:
            yield domain, url


def bulk_insert(conn: sqlite3.Connection, table: str, rows: Iterable[Row]) -> int:
    sql = f"INSERT OR IGNORE INTO {table} (domain, url) VALUES (?, ?)"
    total_before = conn.total_changes
    buffer: list[Row] = []

    for row in rows:
        buffer.append(row)
        if len(buffer) >= BATCH_SIZE:
            conn.executemany(sql, buffer)
            buffer.clear()

    if buffer:
        conn.executemany(sql, buffer)

    return conn.total_changes - total_before


def validate_inputs() -> None:
    missing = [
        str(path)
        for path in (DB_PATH, PHISHTANK_PATH, URLHAUS_PATH, BALANCED_PATH, TOP_DOMAINS_PATH)
        if not path.exists()
    ]
    if missing:
        pretty = "\n - ".join(missing)
        raise FileNotFoundError(f"Required inputs missing:\n - {pretty}")


def main() -> None:
    validate_inputs()

    with sqlite3.connect(DB_PATH) as conn:
        configure_connection(conn)
        create_schema(conn)

        conn.execute("BEGIN IMMEDIATE;")
        safe_inserted = 0
        unsafe_inserted = 0
        try:
            balanced_safe, balanced_unsafe = split_balanced_dataset(BALANCED_PATH)

            safe_inserted += bulk_insert(conn, "safe_links", to_rows(balanced_safe))
            safe_inserted += bulk_insert(
                conn,
                "safe_links",
                to_rows(iter_top_domains(TOP_DOMAINS_PATH)),
            )

            unsafe_sources = (
                to_rows(balanced_unsafe),
                to_rows(iter_phishtank_urls(PHISHTANK_PATH)),
                to_rows(iter_urlhaus_urls(URLHAUS_PATH)),
            )

            for source in unsafe_sources:
                unsafe_inserted += bulk_insert(conn, "unsafe_links", source)

            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("ANALYZE;")
            conn.execute("PRAGMA optimize;")
            conn.execute("VACUUM;")

    print("Safe rows inserted:", safe_inserted)
    print("Unsafe rows inserted:", unsafe_inserted)


if __name__ == "__main__":
    main()
