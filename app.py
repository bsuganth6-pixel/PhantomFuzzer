#!/usr/bin/env python3
"""
PhantomFuzzer — Web Application Fuzzer
Tabs: Fuzz Target | Discover Forms | Reference

Passive detection tool for authorized security testing. Sends
standard, publicly-documented test payloads and observes responses
for signals of injection vulnerabilities. Never attempts exploitation.
"""

import os
import secrets
from flask import Flask, render_template, request, jsonify

from modules import fuzzer, form_parser, payloads

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

MAX_WEB_REQUESTS = 200  # web UI cap; CLI allows higher with explicit flag


@app.route("/")
def index():
    return render_template("index.html", active="fuzz", categories=payloads.CATEGORIES)


@app.route("/discover")
def discover_page():
    return render_template("discover.html", active="discover")


@app.route("/reference")
def reference_page():
    return render_template("reference.html", active="reference")


@app.route("/api/fuzz", methods=["POST"])
def api_fuzz():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    param = (data.get("param") or "").strip()
    categories = data.get("categories") or list(payloads.CATEGORIES.keys())
    method = data.get("method", "GET")
    delay_ms = int(data.get("delay_ms", 250))

    if not url or not param:
        return jsonify({"error": "URL and parameter name are required."}), 400
    if delay_ms < 50:
        return jsonify({"error": "Minimum delay is 50ms — this tool enforces polite rate limits."}), 400

    result = fuzzer.run_fuzz_session(
        url, param, categories=categories, method=method,
        delay_ms=delay_ms, max_requests=MAX_WEB_REQUESTS,
    )
    return jsonify(result)


@app.route("/api/discover-forms", methods=["POST"])
def api_discover_forms():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required."}), 400
    result = form_parser.discover_forms(url)
    return jsonify(result)


@app.route("/api/status")
def api_status():
    return jsonify({"ok": True})


if __name__ == "__main__":
    print(r"""
   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        F U Z Z E R  —  Web Application Vulnerability Scanner
        http://127.0.0.1:5056

        ⚠  Only use against applications you own or are authorized to test.
    """)
    app.run(debug=True, host="127.0.0.1", port=5056)
