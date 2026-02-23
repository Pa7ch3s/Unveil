# Glossary

| Term | Meaning |
|------|---------|
| **ANCHOR** | Persistence / foothold — a way to run again or influence what the app loads (e.g. Qt plugin dir, Windows Run key, Electron preload). |
| **BRIDGE** | Lateral movement — moving between processes or privilege (e.g. helper processes, network, IPC). |
| **BLADE** | Code execution — running attacker-controlled code in the app (e.g. renderer, main process). |
| **Exploitability band** | Summary risk level derived from surfaces and missing roles. |
| **Chainability** | File → ref links: which discovered file references which path or URL (for trust boundaries and "what loads what"). |
| **Attack graph** | Chains of "missing role → vulnerable component → hunt targets" with matched paths from the scan; plus sendable http(s) URLs. |

Unveil models a simple kill chain: get a foothold (ANCHOR), move laterally (BRIDGE), achieve code execution (BLADE). The report highlights what's present and what's missing so you know where to test next.
