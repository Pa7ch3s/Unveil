import argparse
from unveil.core.engine import Engine
from unveil.sensors.bundle import run as bundle

def main():
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("-d", action="store_true")
    p.add_argument("-e", action="store_true")
    p.add_argument("-Of", action="store_true")
    p.add_argument("-S")
    args = p.parse_args()

    eng = Engine(args.target)

    if args.d:
        eng.out["discovery"] = bundle(args.target)

    if args.e:
        pass

    if args.S:
        eng.run_scripts(args.S)

    eng.save()
