import pytest
from unveil.classifier import classify


def test_classify_electron_preload():
    entry = {
        "file": "/app/preload.js",
        "analysis": {"target": "preload.js", "imports": [{"path": "preload.js", "binary": "js", "imports": []}], "entropy": 0},
    }
    out = classify(entry)
    assert "electron_preload" in out["surfaces"]
    assert "ELECTRON_PRELOAD_RCE" in out["exploits"]


def test_classify_qt():
    entry = {
        "file": "/plugins/qt/foo.so",
        "analysis": {"target": "foo.so", "imports": [{"path": "foo.so", "binary": "elf", "imports": ["libQt5Core.so"]}], "entropy": 0},
    }
    out = classify(entry)
    assert "qt_rpath_plugin_drop" in out["surfaces"]


def test_classify_dotnet():
    entry = {
        "file": "/app.dll",
        "analysis": {"target": "app.dll", "imports": [], "entropy": 0, "dotnet": True},
    }
    out = classify(entry)
    assert "dotnet_managed" in out["surfaces"]


def test_classify_packed():
    entry = {
        "file": "/app.exe",
        "analysis": {"target": "app.exe", "imports": [], "entropy": 7.5},
    }
    out = classify(entry)
    assert "PACKED_OR_PROTECTED" in out["exploits"]
