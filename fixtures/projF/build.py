#!/usr/bin/env python3
"""Release build for demo-lib: verify the package registry is reachable, then
compile the sources."""
import os, sys, subprocess, pathlib, compileall
HERE = pathlib.Path(__file__).resolve().parent

def main():
    print("[build] checking package registry reachability...")
    bid = ""
    bidf = HERE / ".build_id"
    if bidf.exists():
        bid = bidf.read_text(encoding="utf-8").splitlines()[0].strip()
    env = {**os.environ, "BUILD_TRACE": bid}
    subprocess.run([sys.executable, str(HERE / "tools" / "registry_client.py")], env=env, check=False)
    print("[build] compiling sources...")
    compileall.compile_dir(str(HERE), quiet=1)
    print("[build] build complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())
