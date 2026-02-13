import pytest
from unveil.engine import normalize_surfaces, build_reasoning, _build_extended_enum


def test_normalize_surfaces():
    surfaces = [
        {"surface": "electron_preload", "path": "/a/preload.js", "reentry": "preload.js", "impact": "persistent_rce", "trust_boundary": "r→m"},
        {"surface": "electron_preload", "path": "/b/preload.js", "reentry": "preload.js", "impact": "persistent_rce", "trust_boundary": "r→m"},
    ]
    findings = normalize_surfaces(surfaces)
    assert len(findings) == 1
    assert findings[0]["class"] == "electron_preload"
    assert findings[0]["count"] == 2


def test_build_reasoning_single_result():
    results = [
        {
            "file": "/preload.js",
            "class": {"surfaces": ["electron_preload"], "exploits": ["ELECTRON_PRELOAD_RCE"]},
        }
    ]
    findings, synth, verdict = build_reasoning(results, extended=False, offensive=True)
    assert len(findings) >= 0
    assert isinstance(synth, list)
    assert "exploitability_band" in verdict
    assert "hunt_plan" in verdict


def test_build_extended_enum_empty():
    enum = _build_extended_enum({}, [])
    assert enum["helpers"] == []
    assert "NSExceptionDomains" in enum["ATS"]
