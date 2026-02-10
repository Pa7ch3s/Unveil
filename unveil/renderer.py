import json

HTML_TEMPLATE = """
<html>
<head>
<title>Unveil Report – {target}</title>
<style>
body {{ background:#0b0f14; color:#eaeaea; font-family: monospace; }}
h1 {{ color:#7afcff; }}
.section {{ margin-bottom:20px; padding:12px; border:1px solid #1f2933; border-radius:6px; }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:4px; background:#1f2933; }}
.critical {{ color:#ff4c4c; }}
.high {{ color:#ffa500; }}
.medium {{ color:#ffd700; }}
.low {{ color:#7aff7a; }}
</style>
</head>
<body>
<h1>UNVEIL – Exploitability Report</h1>
<div class="badge">Target: {target}</div>
<div class="badge {band}">Exploitability: {band}</div>

<div class="section">
<h2>Killchain Verdict</h2>
<pre>{verdict}</pre>
</div>

<div class="section">
<h2>Weaponizable Surfaces</h2>
<pre>{surfaces}</pre>
</div>

<div class="section">
<h2>Exploit Classes</h2>
<pre>{indicators}</pre>
</div>
</body></html>
"""

def render(report):
    band = report["verdict"]["exploitability_band"].lower()
    return HTML_TEMPLATE.format(
        target=report["metadata"]["target"],
        band=band,
        verdict=json.dumps(report["verdict"], indent=2),
        surfaces=json.dumps(report["surfaces"], indent=2),
        indicators=json.dumps(report["synth_indicators"], indent=2)
    )
