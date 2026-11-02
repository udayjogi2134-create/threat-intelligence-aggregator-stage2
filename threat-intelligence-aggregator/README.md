# Threat Intelligence Aggregator (Non-AI)

A defensive, rule-based IOC collection and triage web application built with Python, Streamlit and SQLite.

## Features
- Local CSV, TXT and JSON feed ingestion
- IOC parsing and canonicalization for IP, domain, URL, email and MD5/SHA-1/SHA-256 hashes
- SQLite persistence with distinct source provenance
- Deterministic correlation and configurable heuristic scoring
- Rejection reasons and feed-run history
- Filterable dashboard and CSV/JSON/TXT exports
- Unit tests

## Quick start (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt -r requirements-dashboard.txt
py -m unittest discover -s tests -v
py -m streamlit run app.py
```
Open the local URL Streamlit prints (normally http://localhost:8501).
Do not run `app.py` directly with `python app.py`; Streamlit apps must be
started with `streamlit run` (or `python -m streamlit run`) to create the
Streamlit runtime context.

## Deploy on Vercel
Set the Vercel project's Root Directory to `threat-intelligence-aggregator`.
Vercel uses the lightweight FastAPI entrypoint in `api.py`, keeping Streamlit
and pandas out of the web function's dependencies and cold-start imports. The
Streamlit dashboard dependencies are listed separately in
`requirements-dashboard.txt` and remain available locally with the command
above.
The web dashboard provides indicator listing, manual IOC entry, and CSV/JSON/TXT
exports.

Vercel's `/tmp` storage is temporary and instance-local. The deployed dashboard
therefore does not provide durable or shared SQLite data; configure
`THREAT_INTEL_DB_PATH` only when using a writable mounted database, or replace
SQLite with a managed database for production persistence.

## Sample data
Upload `data/samples/sample_feed.csv` in the sidebar. The sample uses reserved/example indicators and is not a real threat feed.

## Security and limitations
- Scores are illustrative triage heuristics, not verified threat verdicts.
- Do not automatically block indicators from this app without independent validation and approval.
- Public feed URLs are HTTPS-only and redirects are rejected, but a production fetcher should additionally implement a strict hostname allowlist, DNS/IP range checks, response content-type checks, size-limited streaming, rate limiting, and SSRF defenses.
- This starter does not yet implement STIX/TAXII, scheduled jobs, authentication, multi-user authorization, or signed export artifacts.
- Treat imported feed content as untrusted data. Do not render feed HTML or execute feed-provided content.
