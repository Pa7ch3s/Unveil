import os
import subprocess
import tempfile
import shutil
import json
import math
import xml.etree.ElementTree as ET

try:
    import lief
except Exception:
    lief = None

try:
    import pefile
except Exception:
    pefile = None


_analysis_cache = {}
def clear_analysis_cache():
    """Clear per-run analysis cache (call at start of run())."""
    global _analysis_cache
    _analysis_cache = {}


def _run(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    ).stdout.strip()


def _is_macho(path):
    return "Mach-O" in _run(["file", path])


def _is_elf(path):
    return "ELF" in _run(["file", path])


def _is_pe(path):
    out = _run(["file", path])
    return "PE32" in out or "PE32+" in out


def _collect_macho_imports(path):
    if lief:
        try:
            binary = lief.parse(path)
            if binary is None:
                raise RuntimeError("lief returned None")
            libs = getattr(binary, "libraries", []) or []
            return sorted(set(str(l) for l in libs))
        except Exception:
            pass
    imports = set()
    out = _run(["otool", "-L", path])
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line:
            imports.add(line.split(" ")[0])
    return sorted(imports)


def _collect_elf_imports(path):
    if lief:
        try:
            binary = lief.parse(path)
            if binary is None:
                raise RuntimeError("lief returned None")
            libs = getattr(binary, "imported_libraries", []) or []
            return sorted(set(str(l) for l in libs))
        except Exception:
            pass
    imports = set()
    out = _run(["ldd", path])
    for line in out.splitlines():
        if "=>" in line:
            imports.add(line.split("=>")[0].strip())
    return sorted(imports)


def _collect_pe_imports(path):
    imports = set()
    if pefile:
        try:
            pe = pefile.PE(path)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imports.add(entry.dll.decode(errors="ignore"))
        except Exception:
            pass
    return sorted(imports)


def _is_dotnet_assembly(path):
    """True if the PE has a CLR (COM descriptor) directory – i.e. a .NET assembly."""
    if not pefile or not _is_pe(path):
        return False
    try:
        pe = pefile.PE(path)
        if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            return False
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dd) <= 14:
            return False
        com = dd[14]  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        return (com.VirtualAddress != 0 and com.Size != 0)
    except Exception:
        return False


def _inspect_binary(path):
    if _is_macho(path):
        return {
            "type": "macho",
            "imports": _collect_macho_imports(path),
        }

    if _is_elf(path):
        return {
            "type": "elf",
            "imports": _collect_elf_imports(path),
        }

    if _is_pe(path):
        return {
            "type": "pe",
            "imports": _collect_pe_imports(path),
        }

    return None


def _mount_dmg(path):
    mount_dir = tempfile.mkdtemp(prefix="unveil_dmg_")
    _run(["hdiutil", "attach", path, "-nobrowse", "-mountpoint", mount_dir])
    if not os.path.isdir(mount_dir):
        shutil.rmtree(mount_dir, ignore_errors=True)
        return None
    return mount_dir


def _unmount_dmg(mount_dir):
    _run(["hdiutil", "detach", mount_dir])
    shutil.rmtree(mount_dir, ignore_errors=True)


def imports(target):
    if not os.path.exists(target):
        raise FileNotFoundError(target)

    results = []

    if target.lower().endswith(".dmg"):
        mount_dir = _mount_dmg(target)
        if not mount_dir:
            raise RuntimeError("Failed to mount DMG")

        try:
            for root, _, files in os.walk(mount_dir):
                for f in files:
                    path = os.path.join(root, f)
                    info = _inspect_binary(path)
                    if info:
                        results.append(
                            {
                                "path": os.path.relpath(path, mount_dir),
                                "binary": info["type"],
                                "imports": info["imports"],
                            }
                        )
        finally:
            _unmount_dmg(mount_dir)
    else:
        info = _inspect_binary(target)
        if not info:
            # Non-binary (e.g. .js script): return minimal structure so classifier can still run
            base = os.path.basename(target)
            results.append({
                "path": base,
                "binary": "script",
                "imports": [],
            })
        else:
            results.append(
                {
                    "path": os.path.basename(target),
                    "binary": info["type"],
                    "imports": info["imports"],
                }
            )

    return results


def strings(target, min_len=4):
    if not os.path.exists(target):
        raise FileNotFoundError(target)

    out = _run(["strings", "-n", str(min_len), target])
    return out.splitlines()


def entropy(target):
    if not os.path.exists(target):
        raise FileNotFoundError(target)

    with open(target, "rb") as f:
        data = f.read()

    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    ent = 0.0
    for count in freq.values():
        p = count / len(data)
        ent -= p * math.log2(p)

    return round(ent, 4)


RT_MANIFEST = 24  # Windows resource type for embedded app manifest


def _pe_embedded_manifest(path):
    """Extract embedded application manifest from PE (requestedExecutionLevel, etc.). Returns dict or None."""
    if not pefile or not _is_pe(path):
        return None
    try:
        pe = pefile.PE(path)
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if getattr(entry, "id", None) == RT_MANIFEST:
                for sub in entry.directory.entries:
                    try:
                        data_rva = sub.data.struct.OffsetToData
                        size = sub.data.struct.Size
                        img = pe.get_memory_mapped_image()
                        manifest_bytes = img[data_rva : data_rva + size]
                        root = ET.fromstring(manifest_bytes)
                        out = {"target": os.path.basename(path), "requestedExecutionLevel": None}
                        for elem in root.iter():
                            if "requestedExecutionLevel" in (elem.tag or ""):
                                out["requestedExecutionLevel"] = elem.get("level") or ""
                                break
                        return out
                    except Exception:
                        continue
                break
    except Exception:
        pass
    return None


def manifest(target):
    """Extract manifest metadata. PE: embedded app manifest (requestedExecutionLevel). Other formats: stub."""
    if not os.path.exists(target):
        return {"target": os.path.basename(target), "error": "file not found"}
    man = _pe_embedded_manifest(target)
    if man:
        return man
    return {
        "target": os.path.basename(target),
        "note": "Manifest extraction only implemented for PE (embedded manifest)",
    }


def analyze(target):
    try:
        key = os.path.abspath(target)
    except Exception:
        key = target
    if key in _analysis_cache:
        return _analysis_cache[key]
    result = {
        "target": os.path.basename(target),
        "imports": imports(target),
    }
    try:
        result["entropy"] = entropy(target)
    except Exception:
        result["entropy"] = None

    # Tag .NET / CLR assemblies for the managed-code pack
    try:
        result["dotnet"] = _is_dotnet_assembly(target)
    except Exception:
        result["dotnet"] = False

    # Tag runtime (Go, Rust, PyInstaller) from file output for CVE/search
    try:
        ft = _run(["file", "-b", target])
        result["file_type"] = ft or ""
    except Exception:
        result["file_type"] = ""

    _analysis_cache[key] = result
    return result


def tools():
    return {
        "lief": bool(lief),
        "pefile": bool(pefile),
        "otool": shutil.which("otool") is not None,
        "ldd": shutil.which("ldd") is not None,
        "strings": shutil.which("strings") is not None,
    }


def manual():
    return "unveil performs static surface discovery on thick clients before dynamic analysis."
