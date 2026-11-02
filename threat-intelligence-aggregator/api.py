from ipaddress import ip_address
from urllib.parse import urlsplit

import database
import normalizer
import reporting
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

database.init_db()

app = FastAPI(title="Threat Intelligence Aggregator")


class IndicatorRequest(BaseModel):
    type: str = "AUTO"
    value: str


@app.get("/", response_class=HTMLResponse)
def web_dashboard():
    return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Intelligence Aggregator</title><style>
:root{color-scheme:dark;font:15px system-ui;background:#0b1425;color:#e7eefb}body{max-width:1120px;margin:40px auto;padding:0 20px}h1{margin-bottom:6px}p{color:#9db0cc}.card{background:#111e32;border:1px solid #223450;border-radius:14px;padding:20px;margin:18px 0}form{display:flex;gap:10px;flex-wrap:wrap}input,select,button{background:#0b1425;color:#e7eefb;border:1px solid #344966;border-radius:8px;padding:11px}input{flex:1;min-width:220px}button{background:#2563eb;border:0;cursor:pointer}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #223450;overflow-wrap:anywhere}nav{display:flex;gap:12px;margin:18px 0}a{color:#93c5fd}#message{min-height:1.2em;color:#93c5fd}</style></head>
<body><h1>Threat Intelligence Aggregator</h1><p>Defensive IOC collection and triage dashboard</p>
<section class="card"><h2>Add indicator</h2><form id="add"><select name="type"><option>AUTO</option><option>IP</option><option>DOMAIN</option><option>URL</option><option>EMAIL</option><option>HASH</option></select><input name="value" required placeholder="IP, domain, URL, email, or hash"><button>Add indicator</button></form><p id="message" role="status"></p></section>
<section class="card"><h2>Indicators <span id="count"></span></h2><nav><a href="/api/export?format=csv">CSV</a><a href="/api/export?format=json">JSON</a><a href="/api/export?format=txt">TXT</a></nav><div style="overflow:auto"><table><thead><tr><th>Priority</th><th>Score</th><th>Type</th><th>Indicator</th><th>Sources</th><th>Sightings</th><th>Last seen</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<script>
const rows=document.getElementById('rows'),message=document.getElementById('message');
function priority(score){return score>=80?'Critical':score>=60?'High':score>=35?'Medium':'Low'}
async function refresh(){const r=await fetch('/api/indicators');if(!r.ok)throw Error('Could not load indicators');const items=await r.json();document.getElementById('count').textContent=`(${items.length})`;rows.replaceChildren();if(!items.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.textContent='No indicators yet';tr.append(td);rows.append(tr);return}for(const item of items){const tr=document.createElement('tr');for(const value of [priority(item.risk_score),item.risk_score,item.type,item.value,item.sources,item.source_count,item.last_seen]){const td=document.createElement('td');td.textContent=value??'';tr.append(td)}rows.append(tr)}}
document.getElementById('add').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget;message.textContent='';const data=Object.fromEntries(new FormData(form));try{const r=await fetch('/api/indicators',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await r.json();if(!r.ok)throw Error(result.detail||'Could not add indicator');message.textContent=`Added ${result.type}: ${result.value}`;form.reset();await refresh()}catch(err){message.textContent=err.message}});refresh().catch(err=>message.textContent=err.message);
</script></body></html>""")


@app.get("/api/health")
def health_check():
    return {"status": "ok"}


@app.get("/api/indicators")
def get_indicators():
    return database.list_indicators()


@app.post("/api/indicators")
def add_indicator(request: IndicatorRequest):
    value = request.value.strip()
    kind = request.type.strip().upper()
    if kind == "AUTO":
        try:
            ip_address(value)
            kind = "IP"
        except ValueError:
            kind = "URL" if urlsplit(value).scheme else "DOMAIN"
    try:
        canonical_value = normalizer.normalize_ioc(kind, value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    database.upsert_indicators([(kind, canonical_value, "manual")])
    return {"type": kind, "value": canonical_value}


@app.get("/api/export")
def export_indicators(format: str = "csv"):
    rows = database.list_indicators()
    exporters = {
        "csv": (reporting.to_csv, "text/csv", "threat-report.csv"),
        "json": (reporting.to_json, "application/json", "threat-report.json"),
        "txt": (reporting.to_txt, "text/plain", "ioc-list.txt"),
    }
    selected = exporters.get(format.lower())
    if selected is None:
        raise HTTPException(status_code=400, detail="format must be csv, json, or txt")
    exporter, media_type, filename = selected
    return Response(
        exporter(rows),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
