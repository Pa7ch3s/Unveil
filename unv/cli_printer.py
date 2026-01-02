#cat > unveil/cli_printer.py << 'EOF'
import json
import sys
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
DIM = "\033[2m"

def pretty(data):
    band = data.get("verdict", {}).get("exploitability_band", "UNKNOWN")

    color = GREEN
    if band == "CRITICAL": color = RED
    elif band == "HIGH": color = YELLOW

    print(f"{color}UNVEIL REPORT — {band}{RESET}")
    print(DIM + "-"*60 + RESET)

    raw = json.dumps(data, indent=2)
    print(highlight(raw, JsonLexer(), TerminalFormatter()))

