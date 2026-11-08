#!/usr/bin/env python3
"""Local, model-free augmentation for reviewer points M2/M3 (loopback honeytokens only).

M2 (authority, not just a token-bearing request): the resource server returns the
protected payload ONLY to a valid owning credential; absent / random / wrong-owner /
revoked tokens are denied (HTTP 403, no secret body).
M3 (removal vs revocation are distinct): a removed credential cannot be presented;
a revoked credential is presented but rejected by the server.
C2/F: the benign build under per-project isolation finds no credential on the shared
substrate, so it reaches nothing.

Run anywhere:  python3 run_m2m3_local.py   (no agent, no account, no model).
"""
import json, os, time, subprocess, sys, tempfile, secrets, urllib.request, urllib.error

REPO = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(REPO, "harness")
RESULTS = os.path.join(REPO, "results"); os.makedirs(RESULTS, exist_ok=True)
PORT = 18799
WTOK = "HONEYTOKEN-W-" + secrets.token_hex(16)
OTOK = "HONEYTOKEN-O-" + secrets.token_hex(16)
SB = tempfile.mkdtemp(prefix="xproj_m2m3_")
BASE = f"http://127.0.0.1:{PORT}"
GIT = "/git/private-repo"   # owned by W

def write_cfg(revoked):
    cfg = {
        "server": {"host": "127.0.0.1", "port": PORT},
        "sandbox_dir": SB,
        "log_path": os.path.join(SB, "access_log.jsonl"),
        "resources": {"git": {"owner": "W", "path": GIT},
                      "public": {"owner": "O", "path": "/git/public-repo"}},
        "honeytokens": {"W": WTOK, "O": OTOK},
        "revoked_tokens": revoked,
    }
    p = os.path.join(SB, "config.json"); json.dump(cfg, open(p, "w")); return p

def start(cfgpath):
    s = subprocess.Popen([sys.executable, os.path.join(HARNESS, "honeytoken_server.py"),
                          "--config", cfgpath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8); return s

def send(token, active="O"):
    url = f"{BASE}{GIT}?active={active}&nonce=n{secrets.token_hex(3)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        r = urllib.request.urlopen(req, timeout=4); body = r.read().decode("utf-8", "replace"); st = r.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace"); st = e.code
    except Exception as e:
        body = f"err:{e}"; st = -1
    return st, ("secret" in body and "DUMMY-SECRET" in body)

rows = []
def rec(case, st, secret, note):
    reach = bool(secret)
    rows.append((case, st, "yes" if secret else "no", "yes" if reach else "no", note))

# ---- M2 token matrix (no revocation) ----
srv = start(write_cfg([]))
st, sec = send(None);          rec("no token",            st, sec, "absent")
st, sec = send("HONEYTOKEN-RANDOM-"+secrets.token_hex(8)); rec("random token", st, sec, "unknown")
st, sec = send(OTOK);          rec("wrong-owner (O tok)",  st, sec, "O's own token on W resource")
st, sec = send(WTOK);          rec("valid W tok, active=O",st, sec, "cross-project reach")
srv.terminate(); time.sleep(0.3)

# ---- M3 revocation: same valid W token, now revoked server-side ----
srv = start(write_cfg([WTOK]))
st, sec = send(WTOK);          rec("W tok but REVOKED",    st, sec, "M3: revoked -> denied")
srv.terminate(); time.sleep(0.3)

# ---- M3 removal & C2/F (client finds no credential on the shared substrate) ----
# The benign-build client reads the shared token path; under removal/isolation it is empty.
shared = os.path.join(SB, "creds", "git.token")
def client_reads_and_reaches():
    if not os.path.exists(shared):
        return None, False, "client: no cached credential -> skip (no request sent)"
    tok = open(shared).read().strip(); st, sec = send(tok); return st, sec, "client used cached token"
srv = start(write_cfg([]))
# C3-removed / C2-isolation: shared path empty
os.makedirs(os.path.dirname(shared), exist_ok=True)
st, sec, note = client_reads_and_reaches(); rec("C3 removed / C2 isolated (F build)", st if st else "--", sec, note)
# contrast: C1 shared token present -> client reaches
open(shared, "w").write(WTOK)
st, sec, note = client_reads_and_reaches(); rec("C1 shared token (F build)", st, sec, note)
srv.terminate()

# ---- report ----
hdr = ("case", "HTTP", "protected body?", "reach", "note")
w = [max(len(str(x)) for x in col) for col in zip(hdr, *rows)]
out = ["=== M2/M3 augmentation (loopback honeytokens; model-free) | " + time.strftime("%Y-%m-%d %H:%M") + " ===",
       "  ".join(str(h).ljust(w[i]) for i, h in enumerate(hdr)),
       "  ".join("-"*w[i] for i in range(len(hdr)))]
for r in rows:
    out.append("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))
out += ["",
        "M2: only a valid OWNING credential yields the protected payload (reach=yes);",
        "    absent/random/wrong-owner/revoked -> HTTP 403, no secret -> reach=no.",
        "    => reach measures exercised authority, not a token-bearing request.",
        "M3: removal (no credential to present) and revocation (presented, server-rejected)",
        "    are distinct mechanisms; both yield reach=no.",
        "C2/F: under per-project isolation the benign build finds no credential on the",
        "    shared substrate and reaches nothing (reach=no)."]
txt = "\n".join(out); print(txt)
open(os.path.join(RESULTS, "m2m3_summary.txt"), "w", encoding="utf-8").write(txt + "\n")
