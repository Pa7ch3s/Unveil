from unveil.core.enumerate import enumerate_target

import sys, time, json, glob, importlib, os

class Progress:
    def __init__(self, total):
        self.total = max(total,1)
        self.done = 0
    def step(self, label):
        self.done += 1
        pct = int((self.done / self.total) * 100)
        bar = "=" * (pct // 4)
        print(f"\r[{bar:<25}] {pct}% {label}", end="", flush=True)

class Engine:
    def __init__(self, target):
        self.target = target
        self.out = {
            "metadata": {"target": target},
            "discovery": {},
            "enumeration": enumerate_target(self.target),
            "fingerprint": {},
            "probe": {},
            "scripts": {},
            "indicators": [],
            "verdict": None
        }

    def run_scripts(self, pattern):
        base = os.path.join(os.path.dirname(__file__), "..", "scripts")
        base = os.path.abspath(base)
        mods = glob.glob(os.path.join(base, f"{pattern}.py"))
        prog = Progress(len(mods))
        for m in mods:
            name = os.path.basename(m).replace(".py","")
            mod = importlib.import_module(f"unveil.scripts.{name}")
            self.out["scripts"][name] = mod.run(self.target)
            prog.step(f"script:{name}")

    def save(self):
        with open("unveil.json","w") as f:
            json.dump(self.out,f,indent=2)
