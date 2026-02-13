import json
import html as html_module

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Unveil Report – {target}</title>
<style>
body {{ background:#0b0f14; color:#eaeaea; font-family: system-ui, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; }}
h1 {{ color:#7afcff; }}
h2 {{ color:#b0b0b0; margin-top: 1em; }}
.section {{ margin-bottom: 20px; padding: 12px; border: 1px solid #1f2933; border-radius: 6px; }}
.badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; background: #1f2933; margin-right: 8px; }}
.critical {{ color: #ff4c4c; }}
.high {{ color: #ffa500; }}
.medium {{ color: #ffd700; }}
.low {{ color: #7aff7a; }}
pre {{ overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-all; }}
details {{ margin: 8px 0; }}
summary {{ cursor: pointer; font-weight: bold; }}
.discovered-html {{ margin: 12px 0; }}
.discovered-html a {{ color: #7afcff; text-decoration: none; }}
.discovered-html a:hover {{ text-decoration: underline; }}
.discovered-html li {{ margin: 6px 0; }}
</style>
</head>
<body>
<h1>UNVEIL – Exploitability Report</h1>
<div class="badge">Target: {target}</div>
<div class="badge {band}">Exploitability: {band}</div>

{discovered_html_section}

<details class="section" open>
<summary>Killchain Verdict</summary>
<pre>{verdict}</pre>
</details>

<details class="section">
<summary>Weaponizable Surfaces</summary>
<pre>{surfaces}</pre>
</details>

<details class="section">
<summary>Exploit Classes</summary>
<pre>{indicators}</pre>
</details>
</body>
</html>
"""

DISCOVERED_HTML_SECTION = """
<details class="section discovered-html" open>
<summary>Discovered HTML ({count}) – open in browser for attacks, redev, or transparency</summary>
<p>These .html/.htm files were found inside the target. Click to open locally (file://).</p>
<ul>
{links}
</ul>
</details>
"""


def _file_url(path):
    """Return a file:// URL (works when report is opened from disk). Windows: file:///C:/... ; Unix: file:///path."""
    p = path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return "file:///" + p  # Windows drive
    if not p.startswith("/"):
        p = "/" + p
    return "file://" + p


def render(report):
    band = report["verdict"]["exploitability_band"].lower()
    target = html_module.escape(report["metadata"]["target"])
    verdict = html_module.escape(json.dumps(report["verdict"], indent=2))
    surfaces = html_module.escape(json.dumps(report["surfaces"], indent=2))
    indicators = html_module.escape(json.dumps(report["synth_indicators"], indent=2))

    discovered_html = report.get("discovered_html") or []
    if discovered_html:
        links = []
        display_cap = 200
        for path in discovered_html[:display_cap]:
            name = path.split("/")[-1].split("\\")[-1]
            url = _file_url(path)
            safe_path = html_module.escape(path)
            links.append(f'<li><a href="{url}" title="{safe_path}">{html_module.escape(name)}</a></li>')
        count_text = str(len(discovered_html)) + (f" (showing first {display_cap})" if len(discovered_html) > display_cap else "")
        discovered_html_section = DISCOVERED_HTML_SECTION.format(
            count=count_text,
            links="\n".join(links),
        )
    else:
        discovered_html_section = ""

    return HTML_TEMPLATE.format(
        target=target,
        band=band,
        discovered_html_section=discovered_html_section,
        verdict=verdict,
        surfaces=surfaces,
        indicators=indicators,
    )
