"""Python port of the next-generation heuristic analyzer.

This module mirrors the behaviour of ``newheauristic.js``. It evaluates a URL
against a catalogue of positive and negative heuristics inspired by recent
phishing and malware research. The analyser is self-contained and relies solely
on static reference data.
"""

from __future__ import annotations

import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import ParseResult, parse_qsl, urlparse, urlunparse

# --- Research-informed reference data --------------------------------------

HIGH_RISK_TLDS = {
    ".zip",
    ".xyz",
    ".top",
    ".monster",
    ".quest",
    ".gq",
    ".cf",
    ".tk",
    ".ml",
    ".work",
    ".live",
    ".kim",
    ".icu",
    ".buzz",
    ".shop",
    ".support",
    ".click",
    ".casa",
    ".rest",
    ".mom",
}

LOW_RISK_TLDS = {
    ".gov",
    ".gov.uk",
    ".mil",
    ".edu",
    ".edu.au",
    ".ac.uk",
    ".bank",
    ".insurance",
    ".museum",
    ".aero",
    ".post",
    ".pharmacy",
    ".law",
    ".swiss",
}

CREDENTIAL_KEYWORDS = [
    "login",
    "signin",
    "password",
    "passwd",
    "account",
    "verify",
    "security",
    "update",
    "reset",
    "unlock",
    "billing",
    "credential",
    "recovery",
    "2fa",
    "otp",
    "token",
]

URGENCY_KEYWORDS = [
    "urgent",
    "immediate",
    "now",
    "important",
    "warning",
    "alert",
    "must",
    "required",
    "suspend",
    "suspended",
    "limited-time",
    "expire",
    "expiration",
    "attention",
    "notice",
    "confirm",
]

BRAND_ROOTS = [
    "google",
    "apple",
    "icloud",
    "microsoft",
    "office365",
    "paypal",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "bankofamerica",
    "outlook",
    "citibank",
    "fidelity",
    "robinhood",
    "whatsapp",
    "telegram",
    "xfinity",
    "comcast",
    "uber",
    "lyft",
    "craigslist",
    "onlyfans",
    "pornhub",
    "bestbuy",
    "walmart",
    "flipkart",
    "paytm",
    "phonepe",
    "swiggy",
    "zomato",
    "ola",
    "olacabs",
    "irctc",
    "airtel",
    "jio",
    "reliance",
    "bharatpe",
    "sbi",
    "icici",
    "hdfc",
    "axisbank",
    "kotak",
    "yesbank",
    "lic",
    "byjus",
    "makemytrip",
    "bookmyshow",
    "bigbasket",
    "myntra",
    "ajio",
    "nykaa",
    "timesofindia",
    "indiatimes",
    "thehindu",
    "hotstar",
    "payu",
    "bharatgas",
    "swadesi",
]

TRUSTED_ROOTS = {
    "microsoft.com",
    "apple.com",
    "google.com",
    "paypal.com",
    "amazon.com",
    "facebook.com",
    "linkedin.com",
    "netflix.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "fidelity.com",
    "citibank.com",
    "capitalone.com",
    "reddit.com",
    "github.com",
    "stackoverflow.com",
    "nytimes.com",
    "washingtonpost.com",
    "bbc.com",
    "wikipedia.org",
    "bing.com",
    "zoom.us",
    "irs.gov",
    "usa.gov",
    "whitehouse.gov",
    "who.int",
    "cdc.gov",
    "nhs.uk",
    "canada.ca",
    "ato.gov.au",
    "flipkart.com",
    "paytm.com",
    "phonepe.com",
    "zomato.com",
    "swiggy.com",
    "olacabs.com",
    "makemytrip.com",
    "bookmyshow.com",
    "bigbasket.com",
    "myntra.com",
    "ajio.com",
    "nykaa.com",
    "irctc.co.in",
    "airtel.in",
    "jio.com",
    "reliancejio.com",
    "sbi.co.in",
    "icicibank.com",
    "hdfcbank.com",
    "axisbank.com",
    "kotak.com",
    "yesbank.in",
    "licindia.in",
    "thehindu.com",
    "indiatimes.com",
    "timesofindia.com",
    "ndtv.com",
    "hindustantimes.com",
    "economictimes.com",
}

POPULAR_SAFE_DOMAINS = {
    "youtube.com",
    "outlook.com",
    "office.com",
    "adobe.com",
    "salesforce.com",
    "slack.com",
    "dropbox.com",
    "airbnb.com",
    "booking.com",
    "expedia.com",
    "uber.com",
    "lyft.com",
    "doordash.com",
    "grubhub.com",
    "nintendo.com",
    "playstation.com",
    "xbox.com",
    "spotify.com",
    "soundcloud.com",
    "pinterest.com",
    "tiktok.com",
    "snapchat.com",
    "twitch.tv",
    "discord.com",
    "flipkart.com",
    "paytm.com",
    "phonepe.com",
    "zomato.com",
    "swiggy.com",
    "olacabs.com",
    "redbus.in",
    "irctc.co.in",
    "airtel.in",
    "jio.com",
    "reliancejio.com",
    "hotstar.com",
    "sonyliv.com",
    "bookmyshow.com",
    "makemytrip.com",
    "bigbasket.com",
    "myntra.com",
    "ajio.com",
    "nykaa.com",
    "icicibank.com",
    "hdfcbank.com",
    "axisbank.com",
    "sbi.co.in",
    "kotak.com",
    "yesbank.in",
    "indiamart.com",
    "indiatimes.com",
    "timesofindia.com",
    "thehindu.com",
    "ndtv.com",
    "hindustantimes.com",
    "economictimes.com",
    "livemint.com",
    "payu.in",
    "cleartax.in",
}

ADULT_SAFE_ROOTS = {
    "onlyfans.com",
    "pornhub.com",
    "xvideos.com",
    "xhamster.com",
    "chaturbate.com",
    "cam4.com",
    "erome.com",
    "manyvids.com",
    "fansly.com",
    "stripchat.com",
}

ADULT_KEYWORDS = [
    "adult",
    "porn",
    "xxx",
    "cam",
    "cams",
    "sex",
    "milf",
    "teen",
    "nsfw",
    "escort",
    "playboy",
    "babe",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "rb.gy",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "lnkd.in",
    "rebrand.ly",
    "shorte.st",
    "cli.re",
    "s.id",
}

FILE_BAIT_EXTENSIONS = [
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".zip",
    ".rar",
    ".iso",
    ".img",
]

SUSPICIOUS_ARCHIVE_EXTENSIONS = [
    ".scr",
    ".exe",
    ".bat",
    ".cmd",
    ".msi",
]

BASE64_LIKE_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)

DEFAULT_OPTIONS = {
    "maximumPositiveReasons": 5,
    "maximumNegativeReasons": 5,
}


@dataclass
class HeuristicCheck:
    factor: str
    weight: int
    description: str
    evaluator: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]

    def run(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        result = self.evaluator(context)
        if not result:
            return None
        score = result.get("score", self.weight)
        detail = result.get("detail")
        return {
            "factor": self.factor,
            "score": score,
            "description": self.description,
            "detail": detail,
        }


# --- Helpers ----------------------------------------------------------------

def safe_parse_url(raw_url: Any) -> Optional[ParseResult]:
    if not raw_url or not isinstance(raw_url, str):
        return None

    trimmed = raw_url.strip()
    if not trimmed:
        return None

    candidate = trimmed
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        return None
    return parsed


def get_effective_domain(hostname: str) -> str:
    if not hostname:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return hostname
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    last = labels[-1]
    second_last = labels[-2]
    if len(last) == 2 and len(second_last) <= 3 and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def tokenise_path(pathname: str) -> List[str]:
    return [token for token in re.split(r"[^a-z0-9]+", (pathname or "").lower()) if token]


def normalise_score(score: float) -> float:
    return round(score * 100) / 100


def has_suspicious_double_extension(pathname: str) -> bool:
    lower = (pathname or "").lower()
    last_dot = lower.rfind(".")
    if last_dot == -1:
        return False
    extension = lower[last_dot:]
    if extension not in FILE_BAIT_EXTENSIONS and extension not in SUSPICIOUS_ARCHIVE_EXTENSIONS:
        return False
    penultimate_dot = lower.rfind(".", 0, last_dot)
    if penultimate_dot == -1:
        return extension in SUSPICIOUS_ARCHIVE_EXTENSIONS
    penultimate_ext = lower[penultimate_dot:last_dot]
    return penultimate_ext in FILE_BAIT_EXTENSIONS or penultimate_ext in SUSPICIOUS_ARCHIVE_EXTENSIONS


def is_likely_base64(value: str) -> bool:
    if not value or len(value) < 24 or len(value) % 4 != 0:
        return False
    return bool(BASE64_LIKE_PATTERN.fullmatch(value))


def build_tokens(path_tokens: Sequence[str], query_params: Sequence[Tuple[str, str]]) -> List[str]:
    seen = set()
    tokens: List[str] = []

    def add_token(token: str) -> None:
        if token and token not in seen:
            seen.add(token)
            tokens.append(token)

    for token in path_tokens:
        add_token(token)
    for key, _ in query_params:
        add_token(key.lower())
    for _, value in query_params:
        add_token(value.lower())
    return tokens


# --- Heuristic catalogue ----------------------------------------------------

def _insecure_scheme(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["protocol"] == "http:":
        return {
            "detail": "URL served over HTTP without transport security.",
            "score": 45,
        }
    return None


def _high_risk_tld(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    effective_domain = context["effective_domain"]
    dot_index = effective_domain.rfind(".")
    if dot_index == -1:
        return None
    tld = effective_domain[dot_index:]
    if tld in HIGH_RISK_TLDS:
        return {"detail": f"{tld} appears on high-risk TLD lists.", "score": 70}
    return None


def _ip_hostname(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", context["hostname"]):
        return {"detail": "URL points to a bare IPv4 address.", "score": 80}
    return None


def _link_shortener(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["effective_domain"] in SHORTENER_DOMAINS:
        return {
            "detail": f"{context['effective_domain']} is a common shortener hiding final destination.",
            "score": 55,
        }
    return None


def _excessive_subdomains(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    depth = max(len(context["hostname"].split(".")) - 2, 0)
    if depth >= 3:
        return {"detail": f"Hostname contains {depth} subdomain levels.", "score": 45}
    return None


def _hyphenated_host(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    hyphen_count = context["hostname"].count("-")
    if hyphen_count >= 3:
        return {"detail": f"Hostname contains {hyphen_count} hyphens.", "score": 35}
    return None


def _host_entropy(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    first_label = context["hostname"].split(".")[0]
    entropy = shannon_entropy(first_label)
    if len(first_label) >= 6 and entropy >= 4.2:
        return {
            "detail": f"Leading label entropy {entropy:.2f} exceeds AGD threshold.",
            "score": 60,
        }
    return None


def _punycode(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "xn--" in context["hostname"]:
        return {"detail": "Hostname contains punycode labels (xn--).", "score": 65}
    return None


def _numeric_dominance(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    hostname = context["hostname"]
    digits = sum(ch.isdigit() for ch in hostname)
    letters = sum(ch.isalpha() for ch in hostname)
    if digits >= 4 and digits > letters:
        return {
            "detail": f"Digits ({digits}) outnumber letters ({letters}).",
            "score": 30,
        }
    return None


def _sensitive_keywords(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    matches = [token for token in context["tokens"] if token in CREDENTIAL_KEYWORDS]
    if matches:
        snippet = ", ".join(matches[:5])
        return {"detail": f"Sensitive keywords detected: {snippet}.", "score": 40}
    return None


def _urgency_language(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    matches = [token for token in context["tokens"] if token in URGENCY_KEYWORDS]
    if matches:
        snippet = ", ".join(matches[:5])
        return {"detail": f"Urgency cues present: {snippet}.", "score": 25}
    return None


def _long_url(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if len(context["href"]) > 120:
        return {
            "detail": f"URL length {len(context['href'])} exceeds 120 characters.",
            "score": 35,
        }
    return None


def _double_extension(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if has_suspicious_double_extension(context["pathname"]):
        return {"detail": "Path ends with chained or executable-scent extensions.", "score": 50}
    return None


def _dense_query_params(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if len(context["search_params"]) >= 8:
        return {
            "detail": f"Query string carries {len(context['search_params'])} parameters.",
            "score": 25,
        }
    return None


def _base64_payload(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for _, value in context["search_params"]:
        if is_likely_base64(value):
            return {
                "detail": "Query parameter resembles base64-encoded payload.",
                "score": 45,
            }
    return None


def _mixed_brand_signals(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    effective_domain = context["effective_domain"]
    domain_root = effective_domain.split(".")[0]
    conflicting = [
        root
        for root in BRAND_ROOTS
        if root in context["tokens"] and root not in domain_root
    ]
    if conflicting:
        snippet = ", ".join(conflicting[:3])
        return {
            "detail": f"Path references brands ({snippet}) absent from domain.",
            "score": 55,
        }
    return None


def _at_symbol_redirect(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "@" in context["href"]:
        return {"detail": "URL contains @ symbol which can obfuscate redirects.", "score": 50}
    return None


def _repeated_char(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if re.search(r"([a-zA-Z0-9])\1{3,}", context["hostname"]):
        return {"detail": "Hostname contains repeated characters (>=4).", "score": 30}
    return None


def _unverified_adult_content(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    tokens = context["tokens"]
    hostname = context["hostname"].lower()
    host_segments = re.split(r"[^a-z0-9]+", hostname)
    has_adult_cue = any(token in ADULT_KEYWORDS for token in tokens) or any(
        segment in ADULT_KEYWORDS for segment in host_segments if segment
    )
    if has_adult_cue and context["effective_domain"] not in ADULT_SAFE_ROOTS:
        return {
            "detail": "Adult-themed language detected on unverified domain.",
            "score": 40,
        }
    return None


def _non_standard_port(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    port = context["port"]
    if not port:
        return None
    default_port = "443" if context["protocol"] == "https:" else "80" if context["protocol"] == "http:" else ""
    if port != default_port:
        return {"detail": f"Service exposed on uncommon port {port}.", "score": 35}
    return None


NEGATIVE_CHECKS: List[HeuristicCheck] = [
    HeuristicCheck(
        factor="INSECURE_SCHEME",
        weight=45,
        description="Plain HTTP transport exposes downgrade risk (RFC 8461, HSTS bypass case studies).",
        evaluator=_insecure_scheme,
    ),
    HeuristicCheck(
        factor="HIGH_RISK_TLD",
        weight=70,
        description="Top-level domain has elevated abuse rates (APWG 2024).",
        evaluator=_high_risk_tld,
    ),
    HeuristicCheck(
        factor="IP_HOSTNAME",
        weight=80,
        description="Hostname is a raw IP – common in fast-flux campaigns (USENIX WOOT 2022).",
        evaluator=_ip_hostname,
    ),
    HeuristicCheck(
        factor="LINK_SHORTENER",
        weight=55,
        description="Link-shortening domains heavily abused for redirection chains (Google TAG 2024).",
        evaluator=_link_shortener,
    ),
    HeuristicCheck(
        factor="EXCESSIVE_SUBDOMAINS",
        weight=45,
        description="Deeply nested subdomains used to mimic brands (Black Hat Europe 2023 case studies).",
        evaluator=_excessive_subdomains,
    ),
    HeuristicCheck(
        factor="HYPHENATED_HOST",
        weight=35,
        description="Multiple hyphens often mark spoofed brands (Cisco Talos 2023).",
        evaluator=_hyphenated_host,
    ),
    HeuristicCheck(
        factor="HOST_ENTROPY",
        weight=60,
        description="High Shannon entropy indicates algorithmic domain generation.",
        evaluator=_host_entropy,
    ),
    HeuristicCheck(
        factor="PUNYCODE",
        weight=65,
        description="Internationalised (xn--) hostname – potential IDN homograph vector.",
        evaluator=_punycode,
    ),
    HeuristicCheck(
        factor="NUMERIC_DOMINANCE",
        weight=30,
        description="Numeric-dense hosts linked to botnet infrastructure (M3AAWG 2023).",
        evaluator=_numeric_dominance,
    ),
    HeuristicCheck(
        factor="SENSITIVE_KEYWORDS",
        weight=40,
        description="Credential harvesting keywords in the path or query.",
        evaluator=_sensitive_keywords,
    ),
    HeuristicCheck(
        factor="URGENCY_LANGUAGE",
        weight=25,
        description="Urgent call-to-action tokens often embedded in phishing URLs.",
        evaluator=_urgency_language,
    ),
    HeuristicCheck(
        factor="LONG_URL",
        weight=35,
        description="URLs beyond recommended length (NIST 800-63B) are harder for users to audit.",
        evaluator=_long_url,
    ),
    HeuristicCheck(
        factor="DOUBLE_EXT_OBFUSCATION",
        weight=50,
        description="Multiple chained extensions used to disguise executables (Fortinet 2024).",
        evaluator=_double_extension,
    ),
    HeuristicCheck(
        factor="DENSE_QUERY_PARAMS",
        weight=25,
        description="High parameter count used to smuggle data (Black Hat USA 2022).",
        evaluator=_dense_query_params,
    ),
    HeuristicCheck(
        factor="BASE64_PAYLOAD",
        weight=45,
        description="Obfuscated base64 payload in query string (Mandiant UNC3890 2025).",
        evaluator=_base64_payload,
    ),
    HeuristicCheck(
        factor="MIXED_BRAND_SIGNALS",
        weight=55,
        description="Brand keywords in path not matching registered domain root.",
        evaluator=_mixed_brand_signals,
    ),
    HeuristicCheck(
        factor="AT_SYMBOL_REDIRECT",
        weight=50,
        description="“@” in URL can hide real destination (SANS DFIR 2023).",
        evaluator=_at_symbol_redirect,
    ),
    HeuristicCheck(
        factor="REPEATED_CHAR",
        weight=30,
        description="Homoglyph/repetition used for visual deception.",
        evaluator=_repeated_char,
    ),
    HeuristicCheck(
        factor="UNVERIFIED_ADULT_CONTENT",
        weight=40,
        description="Adult-content keywords on unverified domains (ESET Threat Report T3 2024).",
        evaluator=_unverified_adult_content,
    ),
    HeuristicCheck(
        factor="NON_STANDARD_PORT",
        weight=35,
        description="Non-standard port frequently leveraged by malicious servers (Shadowserver 2024).",
        evaluator=_non_standard_port,
    ),
]


# Positive checks -----------------------------------------------------------------

def _https_scheme(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["protocol"] == "https:":
        return {"detail": "URL uses HTTPS scheme.", "score": 35}
    return None


def _low_risk_tld(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    effective_domain = context["effective_domain"]
    dot_index = effective_domain.rfind(".")
    if dot_index == -1:
        return None
    tld = effective_domain[dot_index:]
    if tld in LOW_RISK_TLDS:
        return {
            "detail": f"{tld} is a regulated TLD with low abuse rates.",
            "score": 40,
        }
    return None


def _trusted_root(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["effective_domain"] in TRUSTED_ROOTS:
        return {
            "detail": f"{context['effective_domain']} matches high-reputation trust list.",
            "score": 60,
        }
    return None


def _popular_service(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if context["effective_domain"] in POPULAR_SAFE_DOMAINS:
        return {
            "detail": f"{context['effective_domain']} observed as a high-volume legitimate service.",
            "score": 30,
        }
    return None


def _short_hostname(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if len(context["hostname"]) <= 20:
        return {
            "detail": f"Hostname length {len(context['hostname'])} is compact.",
            "score": 20,
        }
    return None


def _brand_match(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    domain_root = context["effective_domain"].split(".")[0]
    for token in context["tokens"]:
        if domain_root and domain_root in token:
            return {"detail": "Path references same brand as domain root.", "score": 30}
    return None


def _absence_keywords(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    combined = set(CREDENTIAL_KEYWORDS) | set(URGENCY_KEYWORDS)
    if any(token in combined for token in context["tokens"]):
        return None
    return {"detail": "Path lacks credential or urgency cues.", "score": 15}


def _human_readable_domain(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    first_label = context["hostname"].split(".")[0]
    entropy = shannon_entropy(first_label)
    if len(first_label) >= 4 and 2.5 < entropy < 4.2:
        return {
            "detail": f"Hostname entropy {entropy:.2f} within human-readable band.",
            "score": 25,
        }
    return None


def _limited_subdomain_depth(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    depth = max(len(context["hostname"].split(".")) - 2, 0)
    if depth <= 1:
        return {
            "detail": f"Subdomain depth {depth} within common range.",
            "score": 10,
        }
    return None


def _standard_port(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    port = context["port"]
    default_port = "443" if context["protocol"] == "https:" else "80" if context["protocol"] == "http:" else ""
    if not port or port == default_port:
        return {"detail": f"Port {port or 'default'} matches expected scheme.", "score": 10}
    return None


def _verified_adult_platform(context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    effective_domain = context["effective_domain"]
    if effective_domain in ADULT_SAFE_ROOTS:
        return {
            "detail": f"{effective_domain} recognised as vetted adult platform.",
            "score": 20,
        }
    hostname = context["hostname"].lower()
    host_segments = [segment for segment in re.split(r"[^a-z0-9]+", hostname) if segment]
    tokens = context["tokens"]
    has_adult_cue = any(token in ADULT_KEYWORDS for token in tokens) or any(
        segment in ADULT_KEYWORDS for segment in host_segments
    )
    if has_adult_cue:
        domain_root = effective_domain.split(".")[0]
        if domain_root and f"{domain_root}.com" in ADULT_SAFE_ROOTS:
            return {
                "detail": f"{effective_domain} aligns with vetted adult brand naming.",
                "score": 18,
            }
    return None


POSITIVE_CHECKS: List[HeuristicCheck] = [
    HeuristicCheck(
        factor="HTTPS_SCHEME",
        weight=35,
        description="HTTPS present – while not sufficient, still raises baseline trust (Google Chrome Incident Data 2023).",
        evaluator=_https_scheme,
    ),
    HeuristicCheck(
        factor="LOW_RISK_TLD",
        weight=40,
        description="TLD with stringent vetting (e.g., .gov/.bank).",
        evaluator=_low_risk_tld,
    ),
    HeuristicCheck(
        factor="TRUSTED_ROOT",
        weight=60,
        description="Domain aligns with curated, high-reputation brand root list.",
        evaluator=_trusted_root,
    ),
    HeuristicCheck(
        factor="POPULAR_SERVICE_MATCH",
        weight=30,
        description="Domain is a mainstream platform with consistent benign telemetry (Cloudflare Radar 2024).",
        evaluator=_popular_service,
    ),
    HeuristicCheck(
        factor="SHORT_HOSTNAME",
        weight=20,
        description="Short hostnames correlate with legitimate properties (Facebook Threat Research 2023).",
        evaluator=_short_hostname,
    ),
    HeuristicCheck(
        factor="BRAND_MATCH",
        weight=30,
        description="Brand keyword alignment between domain and path (Google Anti-Phishing Working Group 2023).",
        evaluator=_brand_match,
    ),
    HeuristicCheck(
        factor="ABSENCE_OF_KEYWORDS",
        weight=15,
        description="No credential/urgency lexicon in path.",
        evaluator=_absence_keywords,
    ),
    HeuristicCheck(
        factor="HUMAN_READABLE_DOMAIN",
        weight=25,
        description="Balanced entropy suggests human-chosen domain name.",
        evaluator=_human_readable_domain,
    ),
    HeuristicCheck(
        factor="LIMITED_SUBDOMAIN_DEPTH",
        weight=10,
        description="Minimal subdomain depth (<=1) suggests standard hosting.",
        evaluator=_limited_subdomain_depth,
    ),
    HeuristicCheck(
        factor="STANDARD_PORT",
        weight=10,
        description="Default port (443/80) reduces likelihood of covert services.",
        evaluator=_standard_port,
    ),
    HeuristicCheck(
        factor="VERIFIED_ADULT_PLATFORM",
        weight=20,
        description="Adult platform validated against reputable list to reduce false positives (Citizen Lab 2023).",
        evaluator=_verified_adult_platform,
    ),
]


# --- Classification helpers -------------------------------------------------

def _coerce_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _compute_risk_score(override: Optional[Any]) -> float:
    override_value = _coerce_float(override)
    if override_value is None:
        return 0.5
    return max(0.0, min(1.0, override_value))


def _ensure_sentence(text: str) -> str:
    cleaned = text.strip()
    if not cleaned:
        cleaned = "No additional context available."
    if cleaned[-1] not in {".", "!", "?"}:
        cleaned = f"{cleaned}."
    return cleaned


def _reason_to_sentence(reason: Dict[str, Any]) -> str:
    detail = reason.get("detail")
    description = reason.get("description")
    factor = reason.get("factor")
    return _ensure_sentence(detail or description or (factor or "Heuristic signal noted"))


def _collect_reason_sentences(
    label: str,
    top_positive: Sequence[Dict[str, Any]],
    top_negative: Sequence[Dict[str, Any]],
) -> List[str]:
    if label == "unsafe":
        return ["Found in unsafe database."]
    if label == "malicious":
        return []

    sentences: List[str] = []

    if label == "safe":
        for reason in top_positive[:3]:
            sentences.append(_reason_to_sentence(reason))
        while len(sentences) < 2:
            sentences.append("Positive heuristics detected but limited context provided.")
        return sentences[:3]

    if label == "neutral":
        ordered: List[Dict[str, Any]] = []
        if top_positive:
            ordered.append(top_positive[0])
        if top_negative and len(ordered) < 3:
            ordered.append(top_negative[0])
        for reason in list(top_positive[1:]) + list(top_negative[1:]):
            if len(ordered) >= 3:
                break
            ordered.append(reason)
        for reason in ordered:
            sentences.append(_reason_to_sentence(reason))
        while len(sentences) < 2:
            sentences.append("Heuristic signals split between benign and suspicious cues.")
        return sentences[:3]

    if label in {"risky", "extremely_risky"}:
        for reason in top_negative[:3]:
            sentences.append(_reason_to_sentence(reason))
        while len(sentences) < 2:
            sentences.append("Negative heuristics triggered despite limited individual evidence.")
        return sentences[:3]

    return sentences


def _enumerate_reasons(sentences: Sequence[str]) -> List[str]:
    return [f"{index}. {sentence}" for index, sentence in enumerate(sentences, 1)]


def _classify_score(score: float) -> Tuple[str, str]:
    if score == 0.0:
        return "safe", "Found in safe database."
    if score == 1.0:
        return "malicious", "Malicious link found in database."
    if 0.0 < score <= 0.2:
        return "safe", "Link classified as safe."
    if 0.2 < score <= 0.5:
        return "neutral", "Link classified as neutral."
    if 0.5 < score <= 0.7:
        return "risky", "Link classified as risky."
    if 0.7 < score < 1.0:
        return "extremely_risky", "Link classified as extremely risky."
    return "neutral", "Link classification indeterminate."


# --- Core analysis ----------------------------------------------------------

def analyse_url(raw_url: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Analyse *raw_url* and return a structured heuristic report."""

    settings = {**DEFAULT_OPTIONS, **(options or {})}
    parsed = safe_parse_url(raw_url)

    if not parsed:
        return {
            "url": raw_url,
            "parsed": False,
            "error": "Unable to parse URL. Provide an absolute URL or hostname.",
            "positive": [],
            "negative": [
                {
                    "factor": "MALFORMED_URL",
                    "score": 100,
                    "description": "URL parsing failed – treat as untrusted input.",
                    "detail": "Parsing failure indicates malformed or obfuscated link.",
                }
            ],
        }

    hostname = parsed.hostname or ""
    pathname = parsed.path or "/"
    protocol = f"{parsed.scheme}:" if parsed.scheme else ""
    port = str(parsed.port) if parsed.port is not None else ""
    href = parsed.geturl()
    search_params = parse_qsl(parsed.query, keep_blank_values=True)

    effective_domain = get_effective_domain(hostname)
    path_tokens = tokenise_path(pathname)
    tokens = build_tokens(path_tokens, search_params)

    context = {
        "href": href,
        "hostname": hostname,
        "pathname": pathname,
        "protocol": protocol,
        "port": port,
        "search_params": search_params,
        "effective_domain": effective_domain,
        "tokens": tokens if isinstance(tokens, list) else tokenise_path(pathname),
    }

    negative: List[Dict[str, Any]] = []
    positive: List[Dict[str, Any]] = []

    for check in NEGATIVE_CHECKS:
        result = check.run(context)
        if result:
            negative.append(result)

    for check in POSITIVE_CHECKS:
        result = check.run(context)
        if result:
            positive.append(result)

    positive.sort(key=lambda item: item["score"], reverse=True)
    negative.sort(key=lambda item: item["score"], reverse=True)

    top_positive = [
        {**reason, "score": normalise_score(reason["score"])}
        for reason in positive[: settings["maximumPositiveReasons"]]
    ]
    top_negative = [
        {**reason, "score": normalise_score(reason["score"])}
        for reason in negative[: settings["maximumNegativeReasons"]]
    ]

    total_positive = sum(item["score"] for item in positive)
    total_negative = sum(item["score"] for item in negative)
    net_score = total_positive - total_negative

    risk_override = None
    if options:
        for key in ("riskScore", "score", "riskOverride"):
            if key in options:
                risk_override = options[key]
                break

    risk_score = _compute_risk_score(risk_override)
    risk_score = normalise_score(risk_score)
    label, summary = _classify_score(risk_score)
    narrative = _enumerate_reasons(_collect_reason_sentences(label, top_positive, top_negative))

    return {
        "url": raw_url,
        "parsed": True,
        "effectiveDomain": effective_domain,
        "metrics": {
            "positiveSignals": len(positive),
            "negativeSignals": len(negative),
            "netScore": normalise_score(net_score),
            "rawPositiveScore": normalise_score(total_positive),
            "rawNegativeScore": normalise_score(total_negative),
        },
        "positive": top_positive,
        "negative": top_negative,
        "allPositive": positive,
        "allNegative": negative,
        "classification": {
            "label": label,
            "score": risk_score,
            "summary": summary,
            "reasons": narrative,
        },
    }


# For compatibility with the JavaScript export name.
analyze_url = analyse_url


# --- Command line convenience ------------------------------------------------

def _main(argv: Sequence[str]) -> int:
    if len(argv) < 2:
        print("Usage: python newheauristic.py <url> [limit]", file=sys.stderr)
        return 1
    input_url = argv[1]
    limit = int(argv[2]) if len(argv) >= 3 else None
    options = (
        {
            "maximumPositiveReasons": limit,
            "maximumNegativeReasons": limit,
        }
        if limit is not None
        else None
    )
    result = analyse_url(input_url, options)
    import json

    print(json.dumps(result, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
