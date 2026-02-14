"""
P0: .NET assembly identity (name, version) and dangerous API/serialization hints.
Uses dnfile if available; otherwise subprocess (monodis / PowerShell) or minimal fallback.
"""
from pathlib import Path
import subprocess
import re
import xml.etree.ElementTree as ET

# Dangerous assembly refs: having these suggests deserialization/remoting risk
DANGEROUS_ASSEMBLY_REFS = {
    "System.Runtime.Serialization",
    "System.Runtime.Remoting",
    "System.Web.Extensions",  # JavaScriptSerializer
}

# Dangerous type/method name substrings (BinaryFormatter.Deserialize, etc.)
DANGEROUS_TYPE_METHOD_HINTS = [
    "BinaryFormatter",
    "ObjectStateFormatter",
    "NetDataContractSerializer",
    "LosFormatter",
    "ObjectFormatter",
    "SoapFormatter",
    "Type.GetType",
    "Assembly.Load",
    "Assembly.LoadFrom",
    "Activator.CreateInstance",
]

try:
    import dnfile
    from dnfile import dnPE
    _HAS_DNFILE = True
except Exception:
    _HAS_DNFILE = False


def _audit_with_dnfile(path):
    """Extract assembly name, version, refs, and dangerous hints using dnfile."""
    out = {
        "path": path,
        "assembly_name": None,
        "version": None,
        "refs_serialization": False,
        "dangerous_hints": [],
    }
    try:
        pe = dnPE(path)
        if not pe.net or not pe.net.metadata:
            pe.close()
            return out
        tables = getattr(pe.net.metadata, "tables", None)
        if tables:
            # Assembly (this assembly)
            asm_rows = getattr(tables, "Assembly", None)
            if asm_rows and len(asm_rows) > 0:
                asm = asm_rows[0]
                name_val = getattr(asm, "Name", None)
                if name_val is not None:
                    out["assembly_name"] = str(name_val)
                v = getattr(asm, "Version", None)
                if v is not None and hasattr(v, "Major") and hasattr(v, "Minor"):
                    out["version"] = f"{v.Major}.{v.Minor}.{getattr(v, 'Build', 0)}.{getattr(v, 'Revision', 0)}"
            # AssemblyRef
            for ref in (getattr(tables, "AssemblyRef", None) or []):
                try:
                    name = (getattr(ref, "Name", None) or "")
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="ignore")
                    name = str(name).strip()
                    if name in DANGEROUS_ASSEMBLY_REFS:
                        out["refs_serialization"] = True
                        out["dangerous_hints"].append(f"References {name}")
                except Exception:
                    pass
            # MemberRef / TypeRef for dangerous type names
            for hint in DANGEROUS_TYPE_METHOD_HINTS:
                try:
                    for row in (getattr(tables, "MemberRef", None) or []):
                        n = getattr(row, "Name", None)
                        if n and hint.replace(".", "") in (str(n).replace(".", "")):
                            out["dangerous_hints"].append(hint)
                            break
                    for row in (getattr(tables, "TypeRef", None) or []):
                        n = getattr(row, "TypeName", None) or getattr(row, "Name", None)
                        if n and (hint.split(".")[0] in str(n) or hint in str(n)):
                            out["dangerous_hints"].append(hint)
                            break
                except Exception:
                    pass
        out["dangerous_hints"] = list(dict.fromkeys(out["dangerous_hints"]))[:20]
        pe.close()
    except Exception:
        pass
    return out


def _audit_with_monodis(path):
    """Use monodis (Mono) to get assembly name/version and method list."""
    out = {"path": path, "assembly_name": None, "version": None, "refs_serialization": False, "dangerous_hints": []}
    try:
        r = subprocess.run(
            ["monodis", "--assembly", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0 and r.stdout:
            for line in r.stdout.splitlines():
                if "Name:" in line:
                    out["assembly_name"] = line.split("Name:", 1)[-1].strip()
                if "Version:" in line:
                    out["version"] = line.split("Version:", 1)[-1].strip()
        r2 = subprocess.run(
            ["monodis", "--method", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r2.returncode == 0 and r2.stdout:
            text = r2.stdout
            for hint in DANGEROUS_TYPE_METHOD_HINTS:
                if hint.replace(".", "") in text.replace(".", ""):
                    out["dangerous_hints"].append(hint)
            if "System.Runtime.Serialization" in text or "BinaryFormatter" in text:
                out["refs_serialization"] = True
    except Exception:
        pass
    return out


def _audit_with_powershell(path):
    """Windows: use PowerShell to load assembly and get name/version/refs."""
    out = {"path": path, "assembly_name": None, "version": None, "refs_serialization": False, "dangerous_hints": []}
    path_esc = path.replace("'", "''")
    script = f"""
try {{
    $a = [System.Reflection.Assembly]::LoadFile('{path_esc}')
    $n = $a.GetName()
    Write-Output ('NAME:' + $n.Name)
    Write-Output ('VERSION:' + $n.Version.ToString())
    foreach ($r in $a.GetReferencedAssemblies()) {{
        Write-Output ('REF:' + $r.FullName)
    }}
}} catch {{ Write-Output 'ERROR' }}
"""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=str(Path(path).parent) if Path(path).parent else None,
        )
        if r.returncode != 0 or "ERROR" in (r.stdout or ""):
            return out
        for line in (r.stdout or "").splitlines():
            if line.startswith("NAME:"):
                out["assembly_name"] = line[5:].strip()
            elif line.startswith("VERSION:"):
                out["version"] = line[8:].strip()
            elif line.startswith("REF:"):
                ref = line[4:].strip()
                for dang in DANGEROUS_ASSEMBLY_REFS:
                    if dang in ref:
                        out["refs_serialization"] = True
                        out["dangerous_hints"].append(f"References {dang}")
                        break
    except Exception:
        pass
    return out


def _config_hints_for_assembly(assembly_path, max_hints=10):
    """
    Look for same-dir .exe.config or .dll.config; parse for Type.GetType, remoting, assemblyBinding.
    Returns list of short hint strings for report config_hints.
    """
    hints = []
    p = Path(assembly_path)
    if not p.is_file():
        return hints
    # Foo.exe -> Foo.exe.config, Bar.dll -> Bar.dll.config
    config_path = p.parent / (p.name + ".config")
    if not config_path.is_file() or config_path.stat().st_size > 500 * 1024:
        return hints
    try:
        tree = ET.parse(config_path)
        root = tree.getroot()
        raw = ET.tostring(root, method="text", encoding="unicode", default="") or ""
        if "Type.GetType" in raw or "GetType(" in raw:
            hints.append("Config references Type.GetType")
        if "remoting" in raw.lower() or "channel" in raw.lower():
            hints.append("Config has remoting/channel")
        if "assemblyBinding" in raw or "bindingRedirect" in raw:
            hints.append("Config has assemblyBinding/bindingRedirect")
        # Optional: check element tags
        for elem in root.iter():
            tag = (elem.tag or "").split("}")[-1]
            if tag in ("channel", "client", "clientProviders", "assemblyBinding", "dependentAssembly"):
                hints.append(f"Config element: {tag}")
                break
    except Exception:
        pass
    return list(dict.fromkeys(hints))[:max_hints]


def audit_dotnet_assembly(path, max_hints=15):
    """
    Return dict: path, assembly_name, version, refs_serialization, dangerous_hints[, config_hints].
    dangerous_hints capped at max_hints.
    """
    path = str(Path(path).resolve())
    if _HAS_DNFILE:
        out = _audit_with_dnfile(path)
    else:
        import sys
        if sys.platform == "win32":
            out = _audit_with_powershell(path)
        else:
            out = _audit_with_monodis(path)
        if not out.get("assembly_name") and not out.get("dangerous_hints"):
            out["dangerous_hints"] = ["CLR assembly (install dnfile for full analysis)"]
    out["dangerous_hints"] = (out.get("dangerous_hints") or [])[:max_hints]
    config_hints = _config_hints_for_assembly(path)
    if config_hints:
        out["config_hints"] = config_hints
    return out


def run_dotnet_audit(results, max_assemblies=100):
    """
    From scan results, collect all .NET assemblies (analysis.dotnet is True) and audit each.
    Returns list of audit dicts (path, assembly_name, version, refs_serialization, dangerous_hints).
    """
    paths = []
    for r in results:
        if not r:
            continue
        analysis = r.get("analysis") or {}
        if analysis.get("dotnet") is True:
            p = r.get("file")
            if p and isinstance(p, str) and Path(p).is_file():
                paths.append(p)
    paths = list(dict.fromkeys(paths))[:max_assemblies]
    return [audit_dotnet_assembly(p) for p in paths]
