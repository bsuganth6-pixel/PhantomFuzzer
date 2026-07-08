# 🐛 PhantomFuzzer

**Web Application Vulnerability Scanner** — sends standard, publicly-
documented test payloads to detect SQL injection, XSS, command
injection, path traversal, and SSTI. A detection tool, not an
exploitation tool.

Day 7 of the Phantom Security toolkit — the active-testing counterpart
to Day 5's PhantomLog, which analyzes logs *after* an attack; this
finds vulnerabilities *before* one happens.

---

## ⚠️ Responsible use

This tool sends real, active requests to a target — fundamentally
different from Days 5-6's passive analysis. **Only use it against
applications you own or have explicit written authorization to test**
(your own dev/staging environment, or a scope-defined bug bounty
program). It never attempts to extract data, spawn a shell, or exploit
a confirmed finding — it sends a probe and reports what it observes.

Built-in safety defaults reflect this: a 250ms minimum delay between
requests (enforced — the CLI/API reject anything faster), a hard
per-session request cap, and prominent authorization messaging
throughout the UI and CLI.

---

## Testing methodology: a real vulnerable target, not guesswork

Rather than testing detection logic in the abstract, I built a small
intentionally-vulnerable Flask app as a test fixture (`test_target/` —
not part of the shipped product) — the same category as DVWA, OWASP
WebGoat, or Juice Shop: real, deliberately vulnerable practice
applications used exactly for this purpose. It runs on localhost, so
it's outside any network restrictions and gives exact ground truth:
9 endpoints with known, specific vulnerabilities, plus 4 matched safe
controls implementing the exact same functionality correctly.

**This methodology caught three real bugs before they shipped:**

1. **Boolean-blind SQLi detector required the TRUE-condition response
   to match baseline length.** But classic `OR 1=1` injection returns
   *more* rows than a normal single-item lookup, not the same amount —
   so real vulnerable behavior was failing my own check. Fixed to
   compare TRUE vs. FALSE responses against each other, using baseline
   only as a scale reference.

2. **XSS detector false-positived on `javascript:alert(1)`.** That
   payload contains no HTML-significant characters (`<`,`>`,`"`,`'`),
   so HTML-escaping can't change it — its "unescaped" presence proves
   nothing about output encoding. Fixed to only evaluate payloads that
   escaping would actually affect.

3. **Command-injection detector false-positived against a page that
   just echoes input back, unexecuted.** My unique output marker was
   a substring of the payload itself, so simple reflection made it
   "appear" even with zero execution. Worse, the initial fix (check if
   the *raw* payload also appears) still missed cases where benign,
   unrelated HTML-escaping (`&` → `&amp;`) changed the payload's exact
   bytes. Fixed to check raw, HTML-escaped, *and* URL-encoded forms of
   the payload before crediting a marker match as real execution.

**Final verified result — 13/13 test cases:**

| Endpoint | Expected | Result |
|---|---|---|
| SQLi error-based | Detected | ✅ |
| SQLi boolean-blind | Detected | ✅ |
| SQLi time-blind | Detected | ✅ |
| XSS reflected | Detected | ✅ |
| Command injection (output) | Detected | ✅ |
| Command injection (time) | Detected | ✅ |
| Path traversal | Detected | ✅ |
| SSTI | Detected | ✅ |
| Generic anomaly (500 error) | Detected | ✅ |
| XSS — properly escaped | **Zero** findings | ✅ |
| Traversal — validated input | **Zero** findings | ✅ |
| SSTI — no evaluation | **Zero** findings | ✅ |
| Fully clean endpoint, all 6 categories at once | **Zero** findings | ✅ |

Also verified: the request-cap safety limit stops at exactly the
configured number even when more are attempted, and the rate limiter
measurably enforces the configured delay.

---

## Features

| Feature | Web UI | CLI |
|---|---|---|
| SQL injection (error/boolean/time-based) | ✅ | ✅ |
| Reflected XSS detection | ✅ | ✅ |
| Command injection (output/time-based) | ✅ | ✅ |
| Path traversal detection | ✅ | ✅ |
| Server-side template injection (SSTI) | ✅ | ✅ |
| Generic anomaly detection | ✅ | ✅ |
| Automatic form/field discovery | ✅ | ✅ |
| Confidence-rated findings (high/medium/low) | ✅ | ✅ |
| Rate limiting + request cap (enforced) | ✅ | ✅ |
| `--json` output for scripting | — | ✅ |

---

## Setup

```bash
pip install -r requirements.txt

# Web UI → http://127.0.0.1:5056
python3 app.py

# CLI
python3 cli.py --help
```

---

## CLI Usage

```bash
# Fuzz one parameter across all categories
python3 cli.py fuzz http://localhost:3000/search --param q

# Target specific vulnerability classes
python3 cli.py fuzz http://localhost:3000/search --param q --category sqli,xss

# POST requests
python3 cli.py fuzz http://localhost:3000/login --param username --method POST

# Discover forms on a page first
python3 cli.py discover http://localhost:3000/contact

# Adjust politeness / safety limits
python3 cli.py fuzz http://localhost:3000/search --param q --delay-ms 500 --max-requests 100

# JSON output for scripting
python3 cli.py fuzz http://localhost:3000/search --param q --json | jq '.all_findings'
```

**Exit codes:** `0` = no findings · `1` = findings present · `2` = error

---

## How detection works (see the Reference tab for full detail)

Every finding includes a **confidence level** — this is black-box
testing, not source-code analysis, and overclaiming certainty from
observed behavior alone would be dishonest about what automated
detection can actually prove:

- **High** — a strong, specific signal (known DB error string, a
  unique marker executing cleanly, a template expression evaluating)
- **Medium** — a behavioral difference consistent with a vulnerability
  but with more room for coincidence (boolean-response differences,
  borderline timing)
- **Low** — worth a manual look, but a weak/generic signal

**Always manually verify findings** before reporting or remediating —
no automated scanner is a substitute for human judgment.

---

## Project Structure

```
phantomfuzzer/
├── app.py                    ← Flask web UI
├── cli.py                    ← CLI (same modules as web UI)
├── requirements.txt
├── vercel.json
├── modules/
│   ├── payloads.py           ← Standard test payload library, by category
│   ├── http_client.py        ← Rate-limited HTTP client with request cap
│   ├── detectors.py          ← Response analysis engine (the core logic)
│   ├── form_parser.py        ← Auto-discovers forms/fields from a page
│   └── fuzzer.py             ← Orchestration: baseline + payloads + aggregation
├── templates/
│   ├── base.html             ← includes the authorization banner
│   ├── index.html            ← Fuzz Target (main workflow)
│   ├── discover.html         ← Discover Forms
│   └── reference.html        ← Detection methodology + responsible use
└── static/
    ├── css/style.css
    └── js/
        ├── app.js
        └── matrix.js
```

(`test_target/vulnerable_app.py` — the test fixture described above —
is kept in a separate directory outside the shipped product.)

---

*Day 7 of the Phantom Security toolkit. Next up: PhantomIDS.*
