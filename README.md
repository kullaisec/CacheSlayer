# **cacheslayer**


**cacheslayer** — a professional Web Cache Deception (WCD) testing toolkit.

Automates cache-priming (authenticated) → replay (unauthenticated) checks, scores candidate payloads, and produces JSON + DIFF-mode HTML reports showing leaked content (if any). Includes vendor heuristics for Cloudflare / Fastly / Akamai.

  
> ⚠️ **Important:** Use **only** against systems you are explicitly authorized to test (labs, staging, or with written permission). Misuse may expose private data or violate law/policy.

----------

## **Table of contents**

-   [Features](#features)
    
-   [Install](#install)
    
-   [Quickstart](#quickstart)
    
-   [Usage](#usage)
    
-   [How it works (brief)](#how-it-works-brief)
    
-   [Scoring & interpretation](#scoring--interpretation)
    
-   [Outputs](#outputs)
    
-   [Examples](#examples)
    
-   [Vendor heuristics](#vendor-heuristics)
    
-   [Tuning & troubleshooting](#tuning--troubleshooting)
    
    

----------

# **Features**

-   Parse an authenticated curl request (supports zsh $'...' quoting).
    
-   Capture an authenticated baseline (victim) response.
    
-   Generate many WCD candidate payloads (file suffixes, delimiters, encoded traversals, dot segments, odd extensions).
    
-   Optional --vendor-mode to prioritize and add CDN-specific payloads (Cloudflare / Fastly / Akamai).
    
-   Prime cache as victim, then replay as attacker (no auth) and detect cache hits/leaks.
    
-   Heuristic scoring (body similarity + cache evidence + status parity).
    
-   Optional rechecks to catch delayed cache fills.
    
-   Outputs:
    
    -   JSON report (compact, machine-readable).
        
    -   DIFF-mode HTML report with side-by-side victim vs attacker snippets + unified diff.
        
    
-   --verify-ssl toggle (off by default for labs). Suppresses noisy SSL warnings by default.
    

----------

# **Install**

  

Clone the repo and create a Python virtual environment:

```
git clone https://your.repo/cacheslayer.git
cd cacheslayer

# create a venv (recommended)
python3 -m venv cache-venv
source cache-venv/bin/activate
```

----------

# **Quickstart**

  

Create a small file auth_curl.txt containing the authenticated curl command that returns the protected page, for example:

```
curl -i -s -k -X GET \
  -H 'Host: target.example.com' \
  -H 'Accept: text/html' \
  -b 'session=ABCDEFG' \
  'https://target.example.com/my-account'
```

Run the scanner (basic):

```
python3 web_cache_diff.py --curl-file auth_curl.txt --out report.json --html report.html
```

Confirm the prompt by typing YES when asked (this prevents accidental scans).

----------

# **Usage**

```
usage: web_cache_diff.py [-h] (--curl CURL | --curl-file CURL_FILE)
                         [--vendor-mode {cloudflare,fastly,akamai}]
                         [--prime-wait PRIME_WAIT] [--rechecks RECHECKS]
                         [--recheck-wait RECHECK_WAIT] [--threshold THRESHOLD]
                         [--verify-ssl] [--out OUT] [--html HTML]

WCD DIFF scanner (full-featured).

optional arguments:
  -h, --help            show this help message and exit
  --curl CURL           The authenticated curl command (single-line).
  --curl-file CURL_FILE Path to a file containing the authenticated curl command.
  --vendor-mode {cloudflare,fastly,akamai}
                        Enable vendor-specific heuristics.
  --prime-wait PRIME_WAIT
                        Seconds to wait after priming (default: 5).
  --rechecks RECHECKS   Number of rechecks if inconclusive (default: 1).
  --recheck-wait RECHECK_WAIT
                        Seconds to wait between rechecks (default: 5).
  --threshold THRESHOLD Score threshold for vulnerability (0..1). Default: 0.7
  --verify-ssl          Enable strict SSL certificate verification (default: off).
  --out OUT             JSON output path.
  --html HTML           DIFF HTML output path.
```

### **Key flags**

-   --vendor-mode: apply vendor-specific payloads and priorities. Use when you know the CDN.
    
-   --prime-wait: wait time between priming (victim request) and attacker request (default 5s).
    
-   --rechecks and --recheck-wait: how many times and how long to retry if the cache didn’t show evidence on the first try.
    
-   --threshold: adjust sensitivity (lower → more sensitive; higher → fewer false positives).
    
-   --verify-ssl: enable SSL verification (use on production-like targets with valid certs).
    

----------

# **How it works (brief)**

1.  **Parse** the authenticated curl you supply (method, headers, cookies, URL).
    
2.  **Capture baseline**: issue the authenticated request and store the full body/hash/headers.
    
3.  **Generate payloads**: append suffixes or confuse path parsing (e.g., /attacker.css, /my-account;test, /my-account%2F..%2F, etc.).
    
4.  For each payload:
    
    -   **Prime**: request the payload **as victim** (with cookies) to store a version in CDN/edge cache if the server/CDN will cache it.
        
    -   **Wait** (--prime-wait) for caches to settle.
        
    -   **Replay**: request same payload **as attacker** (no auth).
        
    -   **Analyze**: compute similarity between victim baseline and attacker response, check cache headers (Age, X-Cache, Cf-Cache-Status), and status code parity.
        
    -   **Score**: 0.6×similarity + 0.3×(cache evidence) + 0.1×(status match).
        
    -   If score ≥ --threshold and similarity high, the payload is flagged vulnerable.
        

<video controls src="Screen Recording 2025-10-08 at 12.44.44 PM.mov" title="working sample video"></video>

5.  Save reports (JSON + DIFF HTML).
    
### 1. **Cache Priming → Replay → Detection**

               ┌──────────────────────────────────────────────┐
               │         CacheSlayer Scanner              │
               │----------------------------------------------│
               │ ① Victim (Authenticated)  ② Attacker (Anon)  │
               │----------------------------------------------│
               │      |    Prime Cache     |   Replay Cache   │
               │----------------------------------------------│
               │  Baseline + Payload URLs  |  Compare + Score │
               └──────────────────────────────────────────────┘
                            │                     │
                            │                     │
                            ▼                     ▼
               ┌──────────────────────────────────────────────┐
               │                Target Server                 │
               │ (App + CDN/Reverse Proxy + Origin backend)   │
               ├──────────────────────────────────────────────┤
               │  Edge Cache / CDN (Cloudflare, Akamai, etc.) │
               │  ↓                                            │
               │  1️⃣ Victim primes:  /my-account/attacker.css │
               │      ↳ Origin serves private page             │
               │      ↳ CDN caches it (looks static!)          │
               │                                               │
               │  2️⃣ Attacker requests same URL                │
               │      ↳ CDN HIT → same private content served! │
               └──────────────────────────────────────────────┘
### **2. Step-by-Step Workflow with Timing**

```
┌───────────────────────────┐
│  Step 1: Baseline Fetch  │
└──────────┬────────────────┘
           │
           ▼
  Victim → GET /my-account
           (authenticated)
           └─> 200 OK + Private Data
           (stores MD5, body, headers)

┌───────────────────────────┐
│  Step 2: Payload Generate│
└──────────┬────────────────┘
           │
           ▼
  Creates 40–60 variants:
    /my-account/attacker.css
    /my-account;test
    /my-account%2F..%2F
    /my-account/file.webp
    etc.

┌───────────────────────────┐
│  Step 3: Prime Cache     │
└──────────┬────────────────┘
           │
           ▼
  Victim → GET /my-account/attacker.css
           (authenticated)
           └─> 200 OK + Private Data
               CDN stores it (HIT later)

┌───────────────────────────┐
│  Step 4: Attacker Replay │
└──────────┬────────────────┘
           │
           ▼
  Attacker → GET /my-account/attacker.css
              (no cookies)
           └─> 200 OK, X-Cache: HIT,
               Body identical → VULNERABLE!

┌───────────────────────────┐
│  Step 5: Compare & Score │
└──────────┬────────────────┘
           │
           ▼
   Compare:
     Similarity ≥ 0.7 ?
     Cache headers present ?
     Status parity ?

   → Compute final score
     0.6×similarity + 0.3×cache + 0.1×status

┌───────────────────────────┐
│  Step 6: Report Output   │
└──────────┬────────────────┘
           │
           ▼
   - Console: colored summary
   - JSON: machine readable
   - HTML: diff-mode report
     ┌────────────────────────────┐
     │ Victim snippet  | Attacker │
     │ Unified diff    |  Score   │
     └────────────────────────────┘
```

### **3. HTTP Request Flow (Per Payload)**

```
┌─────────────┐
│ Victim Tool │
└─────┬───────┘
      │  (1) Prime
      ▼
┌─────────────┐
│ CDN/Edge    │
└─────┬───────┘
      │ Cache MISS → fetch from origin
      ▼
┌─────────────┐
│ Origin App  │
│ (Authenticated) │
└─────┬───────┘
      │ Response (Private)
      ▼
┌─────────────┐
│ CDN/Edge    │
│ Caches body │
└─────┬───────┘
      │  (2) Replay
      ▼
┌─────────────┐
│ Attacker    │
└─────┬───────┘
      │ GET same payload
      ▼
┌─────────────┐
│ CDN/Edge    │
│ Cache HIT → returns same private data │
└─────────────┘
```

### **4. Detection Logic Diagram**
```
┌───────────────────────────┐
│  Victim Response (Baseline) │
│  len=3824, md5=abc123       │
└──────────┬──────────────────┘
           │
           │
           ▼
┌───────────────────────────┐
│  Attacker Response        │
│  len=3824, md5=abc123     │
│  X-Cache: HIT             │
│  Cache-Control: max-age>0 │
└──────────┬──────────────────┘
           │
           ▼
     ┌─────────────────────────────┐
     │ Compare:                    │
     │ sim=1.0 → identical         │
     │ cache headers → yes         │
     │ status same → yes           │
     │ score = 1.0                 │
     └─────────────────────────────┘
               │
               ▼
     🚨 Flag as VULNERABLE
```
### **5. Scoring Interpretation Table**

| Evidence | Weight | Example | Meaning |
|----------|--------|---------|---------|
| **Body similarity** | 0.6 | `1.0` (identical HTML) | Private data replayed |
| **Cache headers** | 0.3 | `X-Cache: HIT, Age: 10` | Response served from shared cache |
| **Status match** | 0.1 | `200 == 200` | Both look like legit pages |
| **Total ≥ 0.7** | → **Vulnerable** | | High confidence leak |

### **6. HTML Report Structure (visual)**

```
┌───────────────────────────────────────────┐
│ Web Cache Deception — DIFF Report         │
├───────────────────────────────────────────┤
│ Baseline Info                             │
│-------------------------------------------│
│ URL: https://target/my-account            │
│ Status: 200, Body MD5: a756e918...        │
│-------------------------------------------│
│ Vulnerable Payloads                       │
│-------------------------------------------│
│ [VULN] /my-account/attacker.css           │
│   Score: 1.000  Sim: 1.000                │
│   Cache: cache-control:max-age=30         │
│   [View snippets & diff ▼]                │
│     ├─ Victim Snippet                     │
│     ├─ Attacker Snippet                   │
│     └─ Unified Diff (green/red lines)     │
│-------------------------------------------│
│ All Tested Payloads Table (sortable)      │
└───────────────────────────────────────────┘
```
----------

# **Scoring & interpretation**

  

**Score formula**:

```
score = 0.6 * similarity + 0.3 * (cache evidence present ? 1 : 0) + 0.1 * (status parity ? 1 : 0)
```

-   similarity: difflib ratio between baseline and attacker body (0..1).
    
-   cache evidence: presence of headers like Age, X-Cache: HIT, Cf-Cache-Status: HIT or Cache-Control: max-age>0.
    
-   status parity: both responses returned the same status (typically 200).
    

  

**Threshold default**: 0.7.

-   ≥ threshold: high-confidence vulnerability (inspect HTML diff).
    
-   < threshold: low confidence / noise — may need manual review.
    

----------

# **Outputs**

-   **JSON** (--out report.json): structured array of tested payloads with scores, headers, and basic metadata (no full bodies by default).
    
-   **HTML DIFF** (--html report.html): dark-themed interactive report. For flagged payloads it includes:
    
    -   victim snippet
        
    -   attacker snippet
        
    -   unified diff (victim → attacker)
        
    -   cache evidence (Age / X-Cache / Cache-Control)
        
    -   score and similarity
        

These reports make it quick to triage whether a payload actually leaked sensitive info.

----------

# **Examples**

  

Simple run:

```
python3 web_cache_diff.py --curl-file auth_curl.txt --out report.json --html report.html
```

Cloudflare-focused:

```
python3 web_cache_diff.py --curl-file auth_curl.txt --vendor-mode cloudflare --threshold 0.6 --html cf-report.html
```

Strict SSL verification (production):

```
python3 web_cache_diff.py --curl-file auth_curl.txt --verify-ssl --out verified.json
```

Lower threshold (more sensitive / noisy):

```
python3 web_cache_diff.py --curl-file auth_curl.txt --threshold 0.6
```

----------

# **Vendor heuristics**

  

--vendor-mode adds payloads that better match the caching normalizations and quirks of common CDNs:

-   cloudflare: prioritizes static extensions (.js, .css, .json, images) and patterns that Cloudflare historically caches.
    
-   fastly: includes semicolon parameters and variations that may be part of Fastly cache keys.
    
-   akamai: emphasizes encoded slash/dot-segment and session-id patterns.
    


Use vendor mode when you have reason to believe the target uses that CDN. It increases likelihood of hitting real-world caching misconfigurations.

----------

# **Tuning & troubleshooting**

-   **No vulnerable payloads found**: try lowering --threshold (e.g., to 0.60), increase --rechecks, or lengthen --prime-wait for slower caches.
    
-   **False positives**: inspect HTML DIFF for real leakage; sometimes similar templates (shared chrome) look alike but don’t contain secrets.
    
-   **InsecureRequestWarning**: the script suppresses these warnings by default. Use --verify-ssl to enable certificate verification.
    
-   **Timeouts / network errors**: internet or VPN issues can cause failures. Re-run and inspect traces. You can increase timeout in code where do_request() is defined.
    
-   **Large reports**: DIFF HTML can become large for big pages. JSON excludes full bodies to keep sizes small.
 

To contribute:

1.  Fork the repo.
    
2.  Create feature branch.
    
3.  Open a pull request with description & tests.
    