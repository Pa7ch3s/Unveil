# Vision & direction

Unveil aims to be a **thick-client workbench**: one place for the recon that usually requires jumping between CFF Explorer, strings, dnSpy, ProcMon, and Burp. Static analysis first, then a clear attack surface so manual testing can start with a “hot” target list instead of a cold binary.

---

## Where it fits

- **Static advantage** — Automated scanners often fail on custom binaries. Unveil focuses on static analysis first: hardcoded IPs, API keys, and logic surfaces that would otherwise take hours of manual grepping.
- **Proxy gap** — Non-HTTP and thick-client traffic is a common pain. Unveil helps by surfacing endpoints, refs, and chainability so redirecting traffic into Burp (or other tools) is easier.
- **Blind testing** — The report acts as a “flashlight”: attack graph, files touched, persistence points, and suggested surfaces give researchers the hooks to start manual exploitation.

---

## Possible future directions

These are **ideas**, not commitments. They align with making Unveil a “manual testing powerhouse” instead of only a helper.

1. **Vulnerability → test-case mapping**  
   When Unveil finds a surface (e.g. `System.Security.Cryptography` or a specific API), map it to a **manual test checklist** (e.g. “RFC 8017 / PKCS #1: check weak padding or hardcoded IVs”). The tool becomes a mentor that suggests *how* to test what it found.

2. **Process instrumentation (hooking)**  
   Beyond static analysis: a way to influence the app at runtime (e.g. change return values or hook specific functions). A simplified, UI-driven “Frida-lite” for thick clients could lower the bar for researchers who find raw Frida scripting intimidating.

3. **Environmental / permission mapping**  
   Analyze the installation environment: e.g. ACLs on the app directory, “Full Control for Everyone” on the .exe, or other weak file permissions that enable DLL hijacking or tampering. Surfaces that testers often forget to check manually.

---

## Today

The current release focuses on **integration**: one pane for recon (attack graph, checklist, chainability, discovered assets, refs) and a Burp tab to send URLs to Repeater and view results. See the main [README](../README.md) and [Vulnerability mapping](../README.md#vulnerability-mapping) for what Unveil helps discover today.
