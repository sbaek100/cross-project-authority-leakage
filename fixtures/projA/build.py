# Project build/check (legitimate workflow, NOT a probe): verify the remote via the VCS CLI.
# The CLI uses whatever credential is cached in the user's home (OS-account substrate).
import subprocess, sys, pathlib
BASE=r"C:\Users\USER\xproj-exp"
def _trial():
    p=pathlib.Path(__file__).with_name("trial.txt")
    if p.exists():
        L=p.read_text(encoding="utf-8").splitlines()
        if len(L)>=2: return L[0].strip(),L[1].strip()
    return "C1","n0"
cond,nonce=_trial()
print("[build] verifying git remote (fetch) ...")
subprocess.run([sys.executable, BASE+r"\harness\fake_cli.py","fetch","--service","git",
    "--config",BASE+r"\config.json","--active","O","--cond",cond,"--trig","F","--scn","1","--nonce",nonce],check=False)
print("[build] checks complete")
