import os
import plistlib
import re
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


# Patterns for "interesting" strings (URLs, IPs, paths, secrets-related) — pen-test actionable
_INTERESTING_URL = re.compile(r"https?://[^\s\x00]{8,}", re.IGNORECASE)
_INTERESTING_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
_INTERESTING_PATH = re.compile(r"(?:[A-Za-z]:\\|/)(?:[^\s\x00]{3,})?(?:\.(?:exe|dll|so|dylib|config|json|xml|js))\b", re.IGNORECASE)
_INTERESTING_SECRET_KEY = re.compile(r"(?i)(?:api[_-]?key|password|secret|token|auth|bearer|connectionstring)[\s=:][^\s\x00]{4,}")


def interesting_strings(target, max_per_file=100, min_len=6):
    """
    Harvest strings from a binary and return those likely useful for pen testing:
    URLs, IPs, path-like refs, and secret/key-like patterns. Capped per file to keep report size sane.
    """
    if not os.path.exists(target) or not os.path.isfile(target):
        return []
    if shutil.which("strings") is None:
        return []
    try:
        raw = strings(target, min_len=min_len)
    except Exception:
        return []
    seen = set()
    out = []
    for s in raw:
        if len(s) > 500:
            continue
        s_clean = s.strip()
        if not s_clean or s_clean in seen:
            continue
        if _INTERESTING_URL.search(s_clean) or _INTERESTING_IP.search(s_clean):
            seen.add(s_clean)
            out.append(s_clean)
            if len(out) >= max_per_file:
                return out
        elif _INTERESTING_PATH.search(s_clean):
            seen.add(s_clean)
            out.append(s_clean)
            if len(out) >= max_per_file:
                return out
        elif _INTERESTING_SECRET_KEY.search(s_clean):
            seen.add(s_clean)
            out.append(s_clean)
            if len(out) >= max_per_file:
                return out
    return out


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


# Machine constants for PE (partial)
PE_MACHINE = {
    0x014c: "x86",
    0x8664: "x64",
    0xAA64: "ARM64",
}

# Subsystem
PE_SUBSYSTEM = {
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS2 CUI",
    7: "POSIX CUI",
}


def _pe_specifications(path):
    """Extract exact PE specifications (headers + version info) for pen-test actionable detail. Returns dict or None."""
    if not pefile or not _is_pe(path):
        return None
    try:
        pe = pefile.PE(path)
        out = {
            "type": "PE",
            "path": os.path.basename(path),
            "physical_size": os.path.getsize(path) if os.path.isfile(path) else None,
        }
        # FILE_HEADER
        if hasattr(pe, "FILE_HEADER"):
            fh = pe.FILE_HEADER
            out["machine"] = PE_MACHINE.get(getattr(fh, "Machine", None), f"0x{getattr(fh, 'Machine', 0):04x}")
            out["characteristics"] = getattr(fh, "Characteristics", None)
        # OPTIONAL_HEADER (same for 32/64)
        if hasattr(pe, "OPTIONAL_HEADER"):
            oh = pe.OPTIONAL_HEADER
            out["image_size"] = getattr(oh, "SizeOfImage", None)
            out["code_size"] = getattr(oh, "SizeOfCode", None)
            out["initialized_data_size"] = getattr(oh, "SizeOfInitializedData", None)
            out["uninitialized_data_size"] = getattr(oh, "SizeOfUninitializedData", None)
            out["linker_version"] = f"{getattr(oh, 'MajorLinkerVersion', 0)}.{getattr(oh, 'MinorLinkerVersion', 0)}"
            out["os_version"] = f"{getattr(oh, 'MajorOperatingSystemVersion', 0)}.{getattr(oh, 'MinorOperatingSystemVersion', 0)}"
            out["subsystem_version"] = f"{getattr(oh, 'MajorSubsystemVersion', 0)}.{getattr(oh, 'MinorSubsystemVersion', 0)}"
            out["subsystem"] = PE_SUBSYSTEM.get(getattr(oh, "Subsystem", None), str(getattr(oh, "Subsystem", "")))
            out["dll_characteristics"] = getattr(oh, "DLL_Characteristics", None)
            out["stack_reserve"] = getattr(oh, "SizeOfStackReserve", None)
            out["stack_commit"] = getattr(oh, "SizeOfStackCommit", None)
            out["heap_reserve"] = getattr(oh, "SizeOfHeapReserve", None)
            out["heap_commit"] = getattr(oh, "SizeOfHeapCommit", None)
        # Version resource (numeric)
        if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
            v = pe.VS_FIXEDFILEINFO
            fm = getattr(v, "FileVersionMS", 0) or 0
            fl = getattr(v, "FileVersionLS", 0) or 0
            out["file_version"] = f"{(fm >> 16)}.{(fm & 0xFFFF)}.{(fl >> 16)}.{(fl & 0xFFFF)}"
            pm = getattr(v, "ProductVersionMS", 0) or 0
            pl = getattr(v, "ProductVersionLS", 0) or 0
            out["product_version"] = f"{(pm >> 16)}.{(pm & 0xFFFF)}.{(pl >> 16)}.{(pl & 0xFFFF)}"
        # Version strings (FileDescription, LegalCopyright, ProductName, etc.)
        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for fi in pe.FileInfo:
                if hasattr(fi, "StringTable") and fi.StringTable:
                    for st in fi.StringTable:
                        if hasattr(st, "entries") and st.entries:
                            for k, v in st.entries.items():
                                if v and isinstance(v, bytes):
                                    try:
                                        v = v.decode("utf-16-le", errors="replace").strip("\x00")
                                    except Exception:
                                        v = v.decode("utf-8", errors="replace").strip("\x00")
                                out[k.decode("utf-8") if isinstance(k, bytes) else str(k)] = v
        if getattr(pe, "close", None):
            pe.close()
        return out
    except Exception:
        return None


def _macho_specifications(path):
    """Extract Mach-O binary specifications when lief is available. Returns dict or None."""
    if not lief or not _is_macho(path):
        return None
    try:
        binary = lief.parse(path)
        if binary is None:
            return None
        out = {
            "type": "Mach-O",
            "path": os.path.basename(path),
            "physical_size": os.path.getsize(path) if os.path.isfile(path) else None,
        }
        out["format"] = str(binary.format).replace("FORMAT.", "") if hasattr(binary, "format") else None
        if hasattr(binary, "header"):
            h = binary.header
            out["cpu_type"] = str(getattr(h, "cpu_type", ""))
            out["file_type"] = str(getattr(h, "file_type", ""))
        if hasattr(binary, "libraries") and binary.libraries:
            out["libraries_count"] = len(binary.libraries)
        return out
    except Exception:
        return None


def binary_specifications(path):
    """
    Return exact, actionable binary specifications for the given path (PE or Mach-O).
    Used in report summary for pen-test detail (sizes, versions, subsystem, etc.).
    """
    if not path or not os.path.exists(path):
        return None
    if os.path.isdir(path):
        return None
    specs = _pe_specifications(path)
    if specs:
        return specs
    specs = _macho_specifications(path)
    if specs:
        return specs
    # Fallback: minimal file_type + size for any file
    try:
        ft = _run(["file", "-b", path])
        return {
            "type": "file",
            "path": os.path.basename(path),
            "physical_size": os.path.getsize(path),
            "file_type": (ft or "").strip(),
        }
    except Exception:
        return None


def _app_bundle_main_executable(app_path):
    """Return path to main executable inside a macOS .app bundle, or None."""
    if not app_path or not os.path.isdir(app_path):
        return None
    if not app_path.endswith(".app"):
        return None
    contents = os.path.join(app_path, "Contents")
    macos = os.path.join(contents, "MacOS")
    if not os.path.isdir(macos):
        return None
    exe_name = None
    info_plist = os.path.join(contents, "Info.plist")
    if os.path.isfile(info_plist):
        try:
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            exe_name = (plist or {}).get("CFBundleExecutable")
        except Exception:
            pass
    if exe_name:
        candidate = os.path.join(macos, exe_name)
        if os.path.isfile(candidate):
            return candidate
    for name in sorted(os.listdir(macos)):
        candidate = os.path.join(macos, name)
        if os.path.isfile(candidate) and not name.startswith("."):
            return candidate
    return None


def specifications_for_target(path):
    """
    Return specifications for the report (file, directory, or .app bundle).
    For files: same as binary_specifications().
    For .app: main executable's specs plus "bundle" key.
    For other directories: minimal {"type": "directory", "path": ...}.
    """
    if not path or not os.path.exists(path):
        return None
    if os.path.isfile(path):
        return binary_specifications(path)
    if os.path.isdir(path):
        main_exe = _app_bundle_main_executable(path)
        if main_exe:
            specs = binary_specifications(main_exe)
            if specs is not None:
                specs = dict(specs)
                specs["bundle"] = os.path.basename(path.rstrip(os.sep))
                return specs
        return {
            "type": "directory",
            "path": os.path.basename(path.rstrip(os.sep)),
        }
    return None


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


def build_import_summary(results, max_unique=500):
    """
    Build a global list of unique imported library/DLL names from analysis.imports across all results.
    Returns {"libraries": [sorted unique names], "per_file_count": N}.
    """
    libs = set()
    for r in results or []:
        analysis = r.get("analysis") or {}
        imp_list = analysis.get("imports") or []
        for entry in imp_list:
            if not isinstance(entry, dict):
                continue
            for name in (entry.get("imports") or []):
                if name and isinstance(name, str) and len(name) < 300:
                    libs.add(name.strip())
    return {"libraries": sorted(libs)[:max_unique], "per_file_count": len(libs)}


def build_packed_entropy_list(results, entropy_threshold=7.0, max_entries=200):
    """
    List files with high entropy (likely packed/compressed). Returns list of {"path": str, "entropy": float}.
    """
    out = []
    for r in results or []:
        path = r.get("file")
        analysis = r.get("analysis") or {}
        ent = analysis.get("entropy")
        if path and ent is not None and isinstance(ent, (int, float)) and ent >= entropy_threshold:
            out.append({"path": path, "entropy": round(ent, 2)})
        if len(out) >= max_entries:
            break
    return out


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
