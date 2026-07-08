"""
PhantomFuzzer — Form Discovery
═══════════════════════════════════════════════════════════════
Fetches a page and parses out <form> elements — action, method, and
every input field — so a fuzzing target can be discovered
automatically rather than requiring the user to already know every
parameter name.

Uses a simple regex-based parser rather than a full HTML parser
(BeautifulSoup) to keep this dependency-free. Good enough for
well-formed HTML forms, which covers the overwhelming majority of
real-world cases; deliberately malformed/broken HTML may not parse
perfectly, but that's a display page, not a security concern.
"""

import re
import requests
from urllib.parse import urljoin

FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
INPUT_RE = re.compile(r"<input\b([^>]*)/?>", re.IGNORECASE)
TEXTAREA_RE = re.compile(r'<textarea\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE)
SELECT_RE = re.compile(r'<select\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE)
ATTR_RE = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']')


def _parse_attrs(attr_string: str) -> dict:
    return {m.group(1).lower(): m.group(2) for m in ATTR_RE.finditer(attr_string)}


def discover_forms(url: str, timeout: float = 10.0) -> dict:
    """Fetches `url` and returns every form found, with resolved absolute action URLs."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=timeout,
                           headers={"User-Agent": "Mozilla/5.0 (compatible; PhantomFuzzer/1.0)"})
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": str(e), "forms": []}

    html = resp.text
    forms = []

    for form_match in FORM_RE.finditer(html):
        attrs = _parse_attrs(form_match.group(1))
        body = form_match.group(2)

        action = attrs.get("action", "")
        method = attrs.get("method", "GET").upper()
        resolved_action = urljoin(resp.url, action) if action else resp.url

        fields = []
        for input_match in INPUT_RE.finditer(body):
            iattrs = _parse_attrs(input_match.group(1))
            name = iattrs.get("name")
            if name:
                fields.append({
                    "name": name, "type": iattrs.get("type", "text"),
                    "value": iattrs.get("value", ""),
                })

        for m in TEXTAREA_RE.finditer(body):
            fields.append({"name": m.group(1), "type": "textarea", "value": ""})

        for m in SELECT_RE.finditer(body):
            fields.append({"name": m.group(1), "type": "select", "value": ""})

        if fields:
            forms.append({"action": resolved_action, "method": method, "fields": fields})

    return {"success": True, "error": None, "forms": forms, "source_url": resp.url}
