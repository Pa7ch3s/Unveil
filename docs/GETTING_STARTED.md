# Getting started

**One command: CLI + Burp extension (no separate steps)**

| Platform | One-shot install |
|----------|------------------|
| **Linux / macOS** | `curl -sL https://raw.githubusercontent.com/Pa7ch3s/Unveil/main/scripts/install.sh \| bash` |
| **Windows (PowerShell)** | `irm https://raw.githubusercontent.com/Pa7ch3s/Unveil/main/scripts/install.ps1 \| iex` |

This installs the CLI (via pipx or pip), downloads the latest Burp JAR to a standard directory, and on Windows also downloads `unveil-daemon.exe`. At the end you get one set of next steps: load the JAR in Burp, run the daemon if using Burp, then run `unveil -h` for CLI. No clone/build steps required. **Windows:** The scanner uses **LIEF** and in-process string extraction only (no `strings.exe` or other external tools), so the daemon works without adding anything to PATH; the extension can auto-start the daemon from `%LOCALAPPDATA%\Unveil\`.

**Windows — plug and play (no Python/pip):** Prefer the one-command install above. Alternatively, download [unveil-burp-plug-and-play-windows.zip](https://github.com/Pa7ch3s/Unveil/releases) from the latest release. Unzip, load the JAR in Burp, run `unveil-daemon.exe`, and in the Unveil tab keep **Use daemon** checked. Then Scan.

**Windows-only (WIN) variant:** For a dedicated Windows flow with no Python/terminal, run **Setup-Unveil-Windows.ps1** (`irm .../scripts/Setup-Unveil-Windows.ps1 | iex`) or download [Unveil-WIN-plug-and-play.zip](https://github.com/Pa7ch3s/Unveil/releases). It installs **unveil-engine-WIN.exe** and the JAR to `%LOCALAPPDATA%\Unveil\`, adds firewall rule **Unveil-WIN-Internal** (port 8000). The extension auto-starts **unveil-engine-WIN.exe** when you Scan; all labels and assets use the WIN tag to keep this separate from the main engine.

**WSL + Windows Burp:** If you run the daemon in WSL/Kali and Burp on Windows, run `install.ps1` on Windows once: it detects the WSL IP, writes `%USERPROFILE%\.unveil\config.json`, and (as admin) adds a firewall rule so Burp can reach the daemon. The extension loads the daemon URL from that config. In WSL run `UNVEIL_DAEMON_HOST=0.0.0.0 unveil` (or `python -m unveil.daemon`) so the daemon listens on all interfaces. In the Unveil tab use **Test connection** to confirm; then Scan. Findings populate the **Target** site map and **Issue Activity** tab.

**From source (clone then install):**

1. **Clone the repo:** `git clone https://github.com/Pa7ch3s/Unveil.git && cd Unveil`
2. **One-shot from repo:** run `./scripts/install.sh` (Linux/mac) or `.\scripts\install.ps1` (Windows) — same outcome as the curl/irm one-liners above. Or do steps 3–4 manually.
3. **CLI:** `pipx install .` or `pipx install unveil-radar` from PyPI. Run `unveil -h` to confirm.
4. **Burp extension:** `cd unveil-burp && ./gradlew jar` — JAR: `unveil-burp/build/libs/unveil-burp-*.jar`. In Burp: **Extensions** → **Installed** → **Add** → **Java** → select that JAR.
5. **Run a first scan:** **CLI:** `unveil -C /path/to/your/app` (e.g. `.app` or directory; richer: `unveil -C /path/to/app -e -O`). **Burp:** In the Unveil tab, set **Path** (or **Browse…**), click **Scan**. If you see "unveil not found", set **Unveil executable (optional)** to the path from `which unveil`, or enable **Use daemon** and start the daemon (`unveil` or `python -m unveil.daemon`, or on Windows run `unveil-daemon.exe`).
6. **Read the output:** Banner → Nmap-style summary → full JSON. In Burp: **Summary**, **Attack graph** (**Send selected to Repeater** for URLs), **Checklist**, **Discovered assets**, **Chainability**.

**Report at a glance:** **Summary** = high-level verdict and counts; **Attack graph** = what to hunt (missing role → surface → targets); **Checklist** = potential secrets and config risks (with severity); **Discovered assets** = files by type; **Chainability** = which file references which path/URL; **Instrumentation hints** = per-surface hook/Frida suggestions; **Paths to watch** = paths for process monitor correlation.

**Process monitor correlation (P2):** The report includes `paths_to_watch` (install dir, binaries, config paths). In Burp, use the **Paths to watch** tab and **Copy all paths**; then run **ProcMon** (Windows) or **fs_usage** (macOS) filtered to those paths to see what the app actually touches at runtime and correlate with static findings.

**Custom checklist patterns:** Set `UNVEIL_CHECKLIST_EXTRA` to the path of a JSON file. Each entry: `{"pattern_name": "...", "regex": "...", "severity": "credential"|"dangerous_config"|"informational"}`. Built-in patterns have severity (credential, dangerous_config, informational) for prioritization.
