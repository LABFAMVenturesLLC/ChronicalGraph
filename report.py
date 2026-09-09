"""Self-contained, safely escaped HTML report."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .graph import EvidenceGraph
from .models import Finding


def _h(value: object) -> str:
    return html.escape(str(value if value is not None else "—"))


def write_html(graph: EvidenceGraph, findings: list[Finding], output: str | Path) -> Path:
    output_path = Path(output)
    event_rows = "".join(
        f"<tr><td>{_h(event.timestamp.isoformat() if event.timestamp else None)}</td>"
        f"<td>{_h(event.event_type)}</td><td>{_h(event.path or event.url)}</td>"
        f"<td>{_h(event.message)}</td><td><code>{_h(event.id)}</code></td></tr>"
        for event in graph.events.values()
    )
    finding_cards = "".join(
        f"<article class='finding'><span class='badge'>{_h(finding.severity)}</span>"
        f"<h3>{_h(finding.title)}</h3><p>{_h(finding.summary)}</p>"
        f"<p>Confidence: <strong>{finding.confidence:.0%}</strong></p>"
        f"<details><summary>Evidence provenance</summary><ul>"
        + "".join(f"<li><code>{_h(event_id)}</code></li>" for event_id in finding.event_ids)
        + "</ul></details></article>" for finding in findings
    ) or "<p>No built-in hypothesis met its evidence threshold.</p>"
    data = json.dumps({
        "events": [event.as_dict() for event in graph.events.values()],
        "entities": [{"id": e.id, "kind": e.kind, "value": e.value} for e in graph.entities.values()],
        "relations": [relation.as_dict() for relation in graph.relations],
        "findings": [finding.as_dict() for finding in findings],
    }).replace("</", "<\\/")
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ChronicleGraph investigation report</title><style>
:root{{--ink:#17202a;--muted:#627080;--paper:#f4f1ea;--card:#fff;--accent:#b54126;--line:#d9d3c7}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 system-ui,sans-serif}}
header,main{{max-width:1200px;margin:auto;padding:28px}}header{{padding-top:48px}}h1{{font:700 42px Georgia,serif;margin:0}}
.summary{{color:var(--muted);font-size:17px}}.metrics{{display:flex;gap:12px;flex-wrap:wrap}}.metric,.finding{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px}}
.metric strong{{display:block;font-size:28px}}.findings{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}
.badge{{float:right;text-transform:uppercase;color:var(--accent);font-weight:700}}table{{width:100%;border-collapse:collapse;background:var(--card)}}
th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--line);vertical-align:top}}th{{position:sticky;top:0;background:#ece7dc}}
.table-wrap{{max-height:560px;overflow:auto;border:1px solid var(--line);border-radius:10px}}code{{font-size:12px}}input{{width:100%;padding:12px;margin:0 0 10px;border:1px solid var(--line);border-radius:8px}}
</style></head><body><header><h1>ChronicleGraph</h1><p class="summary">Explainable evidence relationships derived from a Plaso timeline.</p>
<div class="metrics"><div class="metric"><strong>{len(graph.events)}</strong>events</div><div class="metric"><strong>{len(graph.entities)}</strong>entities</div><div class="metric"><strong>{len(graph.relations)}</strong>relations</div><div class="metric"><strong>{len(findings)}</strong>findings</div></div></header>
<main><h2>Hypothesis findings</h2><section class="findings">{finding_cards}</section><h2>Timeline</h2>
<input id="filter" placeholder="Filter events…" aria-label="Filter events"><div class="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Type</th><th>Object</th><th>Message</th><th>Evidence ID</th></tr></thead><tbody id="events">{event_rows}</tbody></table></div></main>
<script type="application/json" id="chronicle-data">{data}</script><script>
const input=document.getElementById('filter');input.addEventListener('input',()=>{{const q=input.value.toLowerCase();for(const row of document.querySelectorAll('#events tr'))row.hidden=!row.textContent.toLowerCase().includes(q)}});
</script></body></html>"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(document, encoding="utf-8")
    return output_path

