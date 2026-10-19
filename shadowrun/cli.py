import argparse
import subprocess
import sys

from . import config


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="shadowrun")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("doctor", "up", "down"):
        sub.add_parser(name)
    args = p.parse_args(argv)
    if args.cmd == "doctor":
        from .doctor import run_doctor
        return 0 if run_doctor() else 1
    if args.cmd in ("up", "down"):
        return subprocess.call(["bash", str(config.ROOT / "scripts" / f"{args.cmd}.sh")])
    return 1


if __name__ == "__main__":
    sys.exit(main())
