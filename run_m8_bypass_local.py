#!/usr/bin/env python3
"""TCB / bypass-channel evaluation of the broker (reviewer point M8).

The broker mediates the credentialed resource channel, but complete mediation (P1)
holds only if the launcher ALSO confines the execution environment. This test makes
that boundary empirical instead of asserted: for each channel it measures whether
project O's code can reach W's resource WITHOUT a faithful brokered decision.

Channels (loopback, model-free, honeytokens):
  A filesystem   -- W's token left on a code-readable path -> code reads it, acts
                    directly (bypasses the broker).
  B environment  -- W's token exported in an env var -> code reads it, acts directly.
  C confined     -- token only inside the broker (not on fs/env); direct request has
                    no credential (403) and the broker denies O -> no bypass.
  D identity spoof (broker, identity code-supplied) -- O's code calls the broker but
                    claims project=W -> broker is fooled (authorizes) -> bypass.
  D' identity bound (broker, launcher-stamped id)   -- the launcher binds the id to O,
                    so a claimed W is ignored -> broker denies -> bypass closed.

Run anywhere:  python3 run_m8_bypass_local.py   (no agent/account/model).
"""
import json, os, time, uuid, subprocess, sys, tempfile, secrets
import urllib.request, urllib.error

REPO = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(REPO, "harness")
RESULTS = os.path.join(REPO, "results"); os.makedirs(RESULTS, exist_ok=True)
SRV_PORT, BRK_PORT = 18799, 18800
SB = tempfile.mkdtemp(prefix="xproj_m8_")
WTOK = "HONEYTOKEN-W-" + secrets.token_hex(16)
OTOK = "HONEYTOKEN-O-" + secrets.token_hex(16)
LOG = os.path.join(SB, "access_log.jsonl"); BLOG = os.path.join(SB, "broker_log.jsonl")
SHARED = os.path.join(SB, "creds", "git.token")
BASE = f"http://127.0.0.1:{SRV_PORT}"; GITP = "/git/private-repo"

def write_cfg(bound=None):
    cfg = {"server": {"host": "127.0.0.1", "port": SRV_PORT}, "sandbox_dir": SB, "log_path": LOG,
           "resources": {"git": {"owner": "W", "path": GITP},
                         "public": {"owner": "O", "path": "/git/public-repo"}},
           "honeytokens": {"W": WTOK, "O": OTOK}, "broker_port": BRK_PORT, "broker_log": BLOG}
    if bound: cfg["bound_project"] = bound
    p = os.path.join(SB, f"config_{bound or 'unbound'}.json"); json.dump(cfg, open(p, "w")); return p

def nn(): return "n" + uuid.uuid4().hex[:8]

def start(path, mod):
    return subprocess.Popen([sys.executable, os.path.join(HARNESS, mod), "--config", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def direct_get(token):
    """O's execution code makes its OWN request to W's resource (active=O)."""
    nonce = nn()
    url = BASE + GITP + f"?active=O&nonce={nonce}&cond=m8"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=4) as r: body = r.read().decode("utf-8", "replace"); st = r.status
    except urllib.error.HTTPError as e: body = e.read().decode("utf-8", "replace"); st = e.code
    except Exception as e: body = f"err:{e}"; st = -1
    return st, ("DUMMY-SECRET" in body)

def broker_call(claimed):
    nonce = nn()
    url = f"http://127.0.0.1:{BRK_PORT}/broker/request?project={claimed}&service=git&nonce={nonce}&cond=m8"
    dec = "-"
    try: dec = json.loads(urllib.request.urlopen(url, timeout=4).read()).get("decision")
    except urllib.error.HTTPError as e:
        try: dec = json.loads(e.read()).get("decision")
        except Exception: dec = f"http:{e.code}"
    except Exception as e: dec = f"err:{e}"
    return nonce, dec

rows = []
def rec(channel, bypass, detail):
    rows.append((channel, "YES" if bypass else "no", detail))

srv = start(write_cfg(), "honeytoken_server.py"); time.sleep(0.7)

# A: filesystem channel -- token on a code-readable path
os.makedirs(os.path.dirname(SHARED), exist_ok=True); open(SHARED, "w").write(WTOK)
tok = open(SHARED).read().strip() if os.path.exists(SHARED) else None
st, sec = direct_get(tok); rec("A filesystem (token on readable path)", sec, f"direct GET -> HTTP {st}, secret={'yes' if sec else 'no'}")
os.remove(SHARED)

# B: environment-variable channel -- token in env
os.environ["XPROJ_GIT_TOKEN"] = WTOK
tok = os.environ.get("XPROJ_GIT_TOKEN")
st, sec = direct_get(tok); rec("B environment variable", sec, f"direct GET -> HTTP {st}, secret={'yes' if sec else 'no'}")
del os.environ["XPROJ_GIT_TOKEN"]

# C: confined -- token only in the broker (no fs/env); direct request has no credential
st_noc, sec_noc = direct_get(None)                       # no ambient credential
brk = start(write_cfg(), "broker.py"); time.sleep(0.7)   # unbound broker
_, dec_O = broker_call("O")                               # O asks as itself -> deny
rec("C confined (token only in broker)", bool(sec_noc) or dec_O == "allow",
    f"direct(no cred) HTTP {st_noc}; broker(project=O) -> {dec_O}")

# D: identity spoof -- O's code calls the broker claiming project=W (code-supplied id)
n_spoof, dec_spoof = broker_call("W")
rec("D identity spoof (id code-supplied)", dec_spoof == "allow",
    f"broker(claimed=W) -> {dec_spoof}")
brk.terminate(); time.sleep(0.3)

# D': identity bound by the launcher -- claimed W is ignored, bound to O
brk = start(write_cfg(bound="O"), "broker.py"); time.sleep(0.7)
n_bound, dec_bound = broker_call("W")
brk.terminate(); srv.terminate(); time.sleep(0.2)
# read effective project the broker used for the bound call
eff = "-"
if os.path.exists(BLOG):
    for ln in open(BLOG, encoding="utf-8"):
        if ln.strip():
            e = json.loads(ln)
            if str(e.get("nonce")) == str(n_bound): eff = f"{e.get('claimed_project')}->{e.get('project')}"
rec("D' identity bound (launcher-stamped id)", dec_bound == "allow",
    f"broker(claimed=W, bound=O) -> {dec_bound} [{eff}]")

hdr = ("channel", "bypass?", "detail")
w = [max(len(str(x)) for x in col) for col in zip(hdr, *rows)]
out = ["=== M8: broker TCB / bypass-channel evaluation (loopback, model-free) | "
       + time.strftime("%Y-%m-%d %H:%M") + " ===",
       "bypass? = YES means O reached W's resource (or the broker was fooled) WITHOUT a",
       "faithful brokered decision. 'secret' = the server returned W's protected payload.",
       "",
       "  ".join(str(h).ljust(w[i]) for i, h in enumerate(hdr)),
       "  ".join("-"*w[i] for i in range(len(hdr)))]
for r in rows:
    out.append("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))
out += ["",
        "Reading: the broker closes the credentialed channel only when the launcher also",
        "(1) keeps credentials off every code-readable path (filesystem A, environment B) so",
        "    the only way to act is through the broker (R3), and",
        "(2) stamps an unforgeable project identity the code cannot set (D vs D', R1).",
        "A and B bypass the broker under an unconfined environment; C holds; D is a bypass",
        "when the identity is code-supplied and is closed (D') once the launcher binds it.",
        "This empirically delimits the TCB: complete mediation (P1) is a property of the",
        "confined execution environment plus the broker, not of the broker alone."]
txt = "\n".join(out); print(txt)
open(os.path.join(RESULTS, "m8_bypass_summary.txt"), "w", encoding="utf-8").write(txt + "\n")
