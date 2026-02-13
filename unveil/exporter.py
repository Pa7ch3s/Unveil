import json
from pathlib import Path
from unveil.renderer import render as render_html

def export(json_path, mode):
    json_path = Path(json_path)

    if mode == "txt":
        data = json.loads(json_path.read_text())
        out = json_path.with_suffix(".txt")
        out.write_text(json.dumps(data, indent=2))
        print("Exported:", out)

    elif mode == "html":
        report = json.loads(json_path.read_text())
        html = render_html(report)
        out = json_path.with_suffix(".html")
        out.write_text(html)
        print("Exported:", out)

    else:
        raise ValueError("Unknown export mode")
