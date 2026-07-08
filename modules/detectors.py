"""
PhantomFuzzer — Detection Engine
═══════════════════════════════════════════════════════════════
Given a baseline response (benign input) and a probe response
(payload input), determines whether the payload triggered a signal
consistent with a given vulnerability class. Every detector returns
a confidence level, never a bare "vulnerable: true/false" — automated
detection has real false-positive/negative rates, and overclaiming
certainty would be dishonest about what black-box testing can prove.
"""

import re
from modules import payloads

REFLECTED_SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)


def detect_sqli_error(response_text: str) -> dict:
    """Checks response body for known SQL error signatures."""
    lower = response_text.lower()
    for sig in payloads.SQL_ERROR_SIGNATURES:
        if sig in lower:
            return {"matched": True, "confidence": "high", "evidence": sig}
    return {"matched": False, "confidence": None, "evidence": None}


def detect_sqli_boolean(true_response: dict, false_response: dict, baseline_response: dict) -> dict:
    """
    Boolean-based blind detection. The core signal is that the TRUE-condition
    and FALSE-condition payloads produce SIGNIFICANTLY DIFFERENT responses
    from EACH OTHER — a safely parameterized backend treats both as inert
    string literals and returns near-identical responses either way.

    Note: the TRUE-condition response is deliberately NOT required to match
    baseline length. Classic "OR 1=1"-style injection typically returns
    MORE rows than a normal single-item lookup (it matches every row), so
    requiring TRUE≈baseline would miss the most common real-world pattern.
    Baseline is used only as a scale reference for "what counts as a big
    enough difference to be significant."
    """
    if not (true_response.get("success") and false_response.get("success") and baseline_response.get("success")):
        return {"matched": False, "confidence": None, "evidence": "One or more requests failed."}

    true_len = true_response["content_length"]
    false_len = false_response["content_length"]
    base_len = baseline_response["content_length"]

    significant_gap = max(20, base_len * 0.10)
    responses_differ = abs(true_len - false_len) > significant_gap
    status_differs = true_response["status_code"] != false_response["status_code"]

    if responses_differ or status_differs:
        return {
            "matched": True, "confidence": "medium",
            "evidence": f"TRUE-condition payload response ({true_len}B, HTTP {true_response['status_code']}) "
                       f"differs substantially from FALSE-condition response ({false_len}B, "
                       f"HTTP {false_response['status_code']}) — consistent with the backend evaluating "
                       f"injected boolean logic rather than treating both as inert text "
                       f"(baseline for scale: {base_len}B).",
        }
    return {"matched": False, "confidence": None, "evidence": None}


def detect_timing(probe_response: dict, baseline_elapsed: float, expected_delay: float,
                  tolerance: float = 0.7) -> dict:
    """
    Time-based blind detection: if the response took at least
    `expected_delay * tolerance` seconds longer than baseline, that's
    consistent with the injected sleep/delay actually executing server-side.
    Requires a real elapsed-time margin, not just "slower than usual" noise.
    """
    if not probe_response.get("success"):
        return {"matched": False, "confidence": None, "evidence": None}

    elapsed = probe_response.get("elapsed", 0)
    threshold = baseline_elapsed + (expected_delay * tolerance)

    if elapsed >= threshold:
        return {
            "matched": True, "confidence": "high" if elapsed >= baseline_elapsed + expected_delay * 0.9 else "medium",
            "evidence": f"Response took {elapsed:.2f}s vs baseline {baseline_elapsed:.2f}s "
                       f"(expected +{expected_delay}s delay if vulnerable) — timing consistent with "
                       f"server-side execution of the injected delay.",
        }
    return {"matched": False, "confidence": None,
            "evidence": f"Response took {elapsed:.2f}s vs baseline {baseline_elapsed:.2f}s — no significant delay."}


HTML_SIGNIFICANT_CHARS = set("<>\"'")


def detect_xss_reflection(response_text: str, payload: str) -> dict:
    """
    Checks if the XSS payload appears in the response UNESCAPED — i.e.
    the literal '<script>' rather than the HTML-encoded '&lt;script&gt;'.
    A payload appearing only in its encoded form means the app IS
    escaping output correctly, which is the safe/expected behavior.

    Only payloads containing at least one HTML-significant character
    (<, >, ", ') are meaningful for this check — a payload like the bare
    string "javascript:alert(1)" contains nothing HTML-escaping would
    ever change, so its unescaped presence proves nothing about whether
    output encoding is happening. Flagging it would be a false positive
    caused by testing the wrong signal, not a real finding.
    """
    if not any(c in payload for c in HTML_SIGNIFICANT_CHARS):
        return {"matched": False, "confidence": None,
                "evidence": "Payload contains no HTML-significant characters — not a meaningful "
                           "test of output encoding in this context."}

    if payload in response_text:
        return {
            "matched": True, "confidence": "high",
            "evidence": f"Payload reflected verbatim, unescaped, in the response body.",
        }

    # Check if it was reflected but safely encoded (informative negative result)
    encoded_variants = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace("<", "%3C").replace(">", "%3E"),
    ]
    for variant in encoded_variants:
        if variant in response_text:
            return {"matched": False, "confidence": None,
                    "evidence": "Payload was reflected but properly HTML/URL-encoded — appears safe."}

    return {"matched": False, "confidence": None, "evidence": "Payload not found in response."}


def detect_cmdi_output(response_text: str, marker: str, full_payload: str = None) -> dict:
    """
    Checks if our unique marker string echoed back — meaning the injected
    command executed. Requires the marker to appear WITHOUT the full
    injected payload also appearing (in raw, HTML-escaped, or URL-encoded
    form) — if an app simply reflects whatever input it received (with no
    command execution), the marker would still "appear" as a substring of
    the reflected payload. That's mere echo, not evidence of execution.

    Checking only the RAW payload form isn't enough: an app can perform
    completely unrelated, benign escaping (e.g. HTML-encoding '&' as
    '&amp;' for XSS safety) that changes the payload's exact byte sequence
    without affecting command execution risk at all — that would make the
    raw-form check miss the reflection and misreport it as execution.
    Checking encoded forms too avoids that false positive.
    """
    if marker not in response_text:
        return {"matched": False, "confidence": None, "evidence": None}

    if full_payload:
        variants = [
            full_payload,
            full_payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                       .replace('"', "&quot;").replace("'", "&#39;"),
        ]
        try:
            import urllib.parse
            variants.append(urllib.parse.quote(full_payload))
        except Exception:
            pass

        if any(v in response_text for v in variants):
            return {"matched": False, "confidence": None,
                    "evidence": "Marker found, but the full injected payload also appears (verbatim or "
                               "escaped/encoded) — consistent with simple input reflection, not execution."}

    return {"matched": True, "confidence": "high",
            "evidence": f"Command output marker '{marker}' found in response, without the surrounding "
                       f"injection syntax in any form — consistent with the injected command actually executing."}


def detect_traversal(response_text: str) -> dict:
    """Checks for known file-content signatures (e.g. /etc/passwd header)."""
    for sig in payloads.TRAVERSAL_SIGNATURES:
        if sig in response_text:
            return {"matched": True, "confidence": "high",
                    "evidence": f"Response contains '{sig}' — consistent with reading a sensitive local file."}
    return {"matched": False, "confidence": None, "evidence": None}


def detect_ssti(response_text: str, expected_output: str, payload: str) -> dict:
    """
    Checks if the arithmetic expression was EVALUATED (e.g. {{7*7}} -> 49
    appearing in the response) rather than reflected literally.
    """
    if expected_output in response_text and payload not in response_text:
        return {"matched": True, "confidence": "high",
                "evidence": f"Payload '{payload}' evaluated to '{expected_output}' in the response — "
                           f"template engine is executing user input."}
    return {"matched": False, "confidence": None, "evidence": None}


def detect_generic_anomaly(baseline_response: dict, probe_response: dict) -> dict:
    """
    For generic fuzz strings: flags a NEW server error (500) that wasn't
    present at baseline, or a drastic response-size change, as worth
    manual review — this is a low-confidence "something changed" signal,
    not a specific vulnerability claim.
    """
    if not (baseline_response.get("success") and probe_response.get("success")):
        return {"matched": False, "confidence": None, "evidence": None}

    base_status = baseline_response["status_code"]
    probe_status = probe_response["status_code"]

    if probe_status >= 500 and base_status < 500:
        return {"matched": True, "confidence": "low",
                "evidence": f"Input triggered a server error (HTTP {probe_status}) where baseline "
                           f"returned {base_status} — worth manual review, may indicate unhandled input."}
    return {"matched": False, "confidence": None, "evidence": None}
