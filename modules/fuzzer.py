"""
PhantomFuzzer — Orchestration
═══════════════════════════════════════════════════════════════
Coordinates a fuzzing run: establishes a baseline (benign request),
sends each payload in the chosen category, runs the appropriate
detector, and aggregates findings. One function per category keeps
each detection strategy's logic (error/boolean/timing/reflection)
visible and testable in isolation.
"""

import time
from modules import payloads, detectors
from modules.http_client import RateLimitedClient

BENIGN_VALUE = "testvalue123"


def _build_params(base_params: dict, target_param: str, value: str) -> dict:
    p = dict(base_params or {})
    p[target_param] = value
    return p


def fuzz_sqli(client: RateLimitedClient, url: str, target_param: str, base_params: dict = None,
             method: str = "GET") -> dict:
    findings = []
    send = client.get if method.upper() == "GET" else client.post

    baseline = send(url, _build_params(base_params, target_param, BENIGN_VALUE))
    if not baseline.get("success"):
        return {"category": "sqli", "error": f"Baseline request failed: {baseline.get('error')}", "findings": []}

    # Error-based
    for payload in payloads.SQLI_ERROR_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, payload))
        if resp.get("success"):
            result = detectors.detect_sqli_error(resp["text"])
            if result["matched"]:
                findings.append({"type": "sqli_error", "payload": payload, **result})

    # Boolean-based blind
    for true_payload, false_payload in payloads.SQLI_BOOLEAN_PAIRS:
        true_resp = send(url, _build_params(base_params, target_param, true_payload))
        false_resp = send(url, _build_params(base_params, target_param, false_payload))
        result = detectors.detect_sqli_boolean(true_resp, false_resp, baseline)
        if result["matched"]:
            findings.append({"type": "sqli_boolean", "payload": f"{true_payload} / {false_payload}", **result})

    # Time-based blind
    baseline_elapsed = baseline.get("elapsed", 0)
    for entry in payloads.SQLI_TIME_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, entry["payload"]))
        result = detectors.detect_timing(resp, baseline_elapsed, entry["delay"])
        if result["matched"]:
            findings.append({"type": "sqli_time", "payload": entry["payload"], "engine": entry["engine"], **result})

    return {"category": "sqli", "error": None, "findings": findings, "payloads_tested": _count_sqli_payloads()}


def _count_sqli_payloads():
    return (len(payloads.SQLI_ERROR_PAYLOADS) + len(payloads.SQLI_BOOLEAN_PAIRS) * 2
            + len(payloads.SQLI_TIME_PAYLOADS))


def fuzz_xss(client: RateLimitedClient, url: str, target_param: str, base_params: dict = None,
            method: str = "GET") -> dict:
    findings = []
    send = client.get if method.upper() == "GET" else client.post

    for payload in payloads.XSS_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, payload))
        if resp.get("success"):
            result = detectors.detect_xss_reflection(resp["text"], payload)
            if result["matched"]:
                findings.append({"type": "xss_reflected", "payload": payload, **result})

    return {"category": "xss", "error": None, "findings": findings, "payloads_tested": len(payloads.XSS_PAYLOADS)}


def fuzz_cmdi(client: RateLimitedClient, url: str, target_param: str, base_params: dict = None,
              method: str = "GET") -> dict:
    findings = []
    send = client.get if method.upper() == "GET" else client.post

    baseline = send(url, _build_params(base_params, target_param, BENIGN_VALUE))
    baseline_elapsed = baseline.get("elapsed", 0) if baseline.get("success") else 0

    for payload in payloads.CMDI_OUTPUT_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, payload))
        if resp.get("success"):
            result = detectors.detect_cmdi_output(resp["text"], payloads.CMDI_MARKER, full_payload=payload)
            if result["matched"]:
                findings.append({"type": "cmdi_output", "payload": payload, **result})

    for entry in payloads.CMDI_TIME_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, entry["payload"]))
        result = detectors.detect_timing(resp, baseline_elapsed, entry["delay"])
        if result["matched"]:
            findings.append({"type": "cmdi_time", "payload": entry["payload"], **result})

    total = len(payloads.CMDI_OUTPUT_PAYLOADS) + len(payloads.CMDI_TIME_PAYLOADS)
    return {"category": "cmdi", "error": None, "findings": findings, "payloads_tested": total}


def fuzz_traversal(client: RateLimitedClient, url: str, target_param: str, base_params: dict = None,
                   method: str = "GET") -> dict:
    findings = []
    send = client.get if method.upper() == "GET" else client.post

    for payload in payloads.TRAVERSAL_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, payload))
        if resp.get("success"):
            result = detectors.detect_traversal(resp["text"])
            if result["matched"]:
                findings.append({"type": "path_traversal", "payload": payload, **result})

    return {"category": "traversal", "error": None, "findings": findings,
            "payloads_tested": len(payloads.TRAVERSAL_PAYLOADS)}


def fuzz_ssti(client: RateLimitedClient, url: str, target_param: str, base_params: dict = None,
              method: str = "GET") -> dict:
    findings = []
    send = client.get if method.upper() == "GET" else client.post

    for entry in payloads.SSTI_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, entry["payload"]))
        if resp.get("success"):
            result = detectors.detect_ssti(resp["text"], entry["expect"], entry["payload"])
            if result["matched"]:
                findings.append({"type": "ssti", "payload": entry["payload"], "engine": entry["engine"], **result})

    return {"category": "ssti", "error": None, "findings": findings, "payloads_tested": len(payloads.SSTI_PAYLOADS)}


def fuzz_generic(client: RateLimitedClient, url: str, target_param: str, base_params: dict = None,
                 method: str = "GET") -> dict:
    findings = []
    send = client.get if method.upper() == "GET" else client.post

    baseline = send(url, _build_params(base_params, target_param, BENIGN_VALUE))

    for payload in payloads.GENERIC_FUZZ_PAYLOADS:
        resp = send(url, _build_params(base_params, target_param, payload))
        result = detectors.detect_generic_anomaly(baseline, resp)
        if result["matched"]:
            findings.append({"type": "generic_anomaly", "payload": payload[:60], **result})

    return {"category": "generic", "error": None, "findings": findings,
            "payloads_tested": len(payloads.GENERIC_FUZZ_PAYLOADS)}


FUZZ_FUNCS = {
    "sqli": fuzz_sqli, "xss": fuzz_xss, "cmdi": fuzz_cmdi,
    "traversal": fuzz_traversal, "ssti": fuzz_ssti, "generic": fuzz_generic,
}


def run_fuzz_session(url: str, target_param: str, categories: list = None, base_params: dict = None,
                     method: str = "GET", delay_ms: int = 250, timeout: float = 10,
                     max_requests: int = 500, headers: dict = None, cookies: dict = None) -> dict:
    """
    Runs one or more payload categories against a single target parameter.
    Returns a combined report with all findings, total requests sent, and
    per-category breakdown.
    """
    categories = categories or list(FUZZ_FUNCS.keys())
    client = RateLimitedClient(delay_ms=delay_ms, timeout=timeout, max_requests=max_requests,
                               headers=headers, cookies=cookies)

    results = {}
    all_findings = []
    start_time = time.time()

    for category in categories:
        fn = FUZZ_FUNCS.get(category)
        if not fn:
            results[category] = {"category": category, "error": f"Unknown category: {category}", "findings": []}
            continue
        cat_result = fn(client, url, target_param, base_params=base_params, method=method)
        results[category] = cat_result
        for f in cat_result["findings"]:
            f["category"] = category
            all_findings.append(f)

    elapsed = time.time() - start_time
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(key=lambda f: sev_rank.get(f.get("confidence"), 3))

    return {
        "url": url, "target_param": target_param, "method": method,
        "categories_tested": categories, "results": results,
        "all_findings": all_findings, "total_findings": len(all_findings),
        "total_requests": client.request_count, "elapsed_seconds": round(elapsed, 2),
        "capped": client.request_count >= max_requests,
    }
