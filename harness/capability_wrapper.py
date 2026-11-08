# CapScope-style capability gate on the COMMAND (arg-prefix allowlist).
# Shows: constraining the command name/args does NOT constrain the authority held in the substrate
# (a probe that reads the cached token directly reaches W's resource regardless).
import sys, subprocess
ALLOW=[["fetch","--service","git","--repo","public-repo"]]   # only the public repo command is allowed
args=sys.argv[1:]
ok=any(args[:len(p)]==p for p in ALLOW)
if not ok:
    sys.stderr.write("[capability] DENIED by command allowlist: "+" ".join(args)+"\n"); sys.exit(13)
sys.exit(subprocess.run([sys.executable]+args).returncode)
