import os
import subprocess
import tempfile
import shutil
import json
import math

try:
    import lief
except Exception:
    lief = None

try:
    import pefile
except Exception:
    pefile = None


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
    imports = set()
    out = _run(["otool", "-L", path])
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line:
            imports.add(line.split(" ")[0])
    return sorted(imports)


def _collect_elf_imports(path):
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
            raise RuntimeError("Unsupported or non-binary file")

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


def manifest(target):
    return {
        "note": "Manifest extraction not implemented yet",
        "target": os.path.basename(target),
    }


def analyze(target):
    result = {
        "target": os.path.basename(target),
        "imports": imports(target),
    }

    try:
        result["entropy"] = entropy(target)
    except Exception:
        result["entropy"] = None

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
