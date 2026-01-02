#cat > unveil/core/surface_synth.py << 'EOF'
def synthesize(surfaces):
    indicators = []

    for s in surfaces:
        name = s.get("surface")

        if name == "preload_write":
            indicators.append({"class": "electron_asar_preload", "impact": "ASAR preload RCE chain"})

        if name == "ipc_helper":
            indicators.append({"class": "electron_helper_ipc", "impact": "Helper IPC trust boundary escape"})

        if name == "network_mitm":
            indicators.append({"class": "ats_mitm_downgrade", "impact": "Local MITM + TLS downgrade"})

        if name == "electron_preload":
            indicators.append({"class": "electron_asar_preload", "impact": "Electron preload persistence"})

        if name == "electron_helper":
            indicators.append({"class": "electron_helper_ipc", "impact": "Electron helper lateral execution"})

    return indicators


