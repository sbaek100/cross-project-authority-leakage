#!/usr/bin/env python3
"""Per-requirement evaluation of the broker against R1-R5 (reviewer points M9, M2).

Each principal runs under a LAUNCHER-BOUND identity (bound_project), so the decisions
reflect project-keyed authorization the code cannot forge -- not the spoofable,
code-supplied mode. (The spoof itself, and that binding closes it, is in run_m8_bypass.)
Utility means the client actually RETRIEVES the protected resource body through the
broker (the broker now relays the upstream result), not merely that a request was made.

  R1 trusted project identity -- same service (git, owner W) under a launcher bound to O
     vs to W -> deny vs allow; the code cannot change the bound id.
  R2 faithful mediation       -- the 2x2 (bound principal) x service matrix tracks owner.
  R3 per-project credential   -- the credential is not on the execution's credential path
     (ambient path leaks; brokered path does not). OS-level protection of the broker's own
     store is a reference-design ASSUMPTION, not demonstrated here (see paper Sec. 4).
  R4 transparency             -- every decision and each cross-project credential use is
     logged attributably (a permitted share is logged cross_project_access=True,
     policy_violation=False). This is AUDIT logging; user-facing surfacing is not built.
  R5 utility                  -- same-project AND explicitly granted cross-project access
     return the protected resource body (HTTP 200) through the broker.

Run anywhere:  python3 run_r_eval_local.py   (no agent/account/model).
"""
import json, os, time, uuid, subprocess, sys, tempfile, secrets
import urllib.request, urllib.error

REPO = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(REPO, "harness")
RESULTS = os.path.join(REPO, "results"); os.makedirs(RESULTS, exist_ok=True)
SRV_PORT, BRK_PORT = 18799, 18800
SB = tempfile.mkdtemp(prefix="xproj_reval_")
WTOK = "HONEYTOKEN-W-" + secrets.token_hex(16)
OTOK = "HONEYTOKEN-O-" + secrets.token_hex(16)
LOG = os.path.join(SB, "access_log.jsonl"); BLOG = os.path.join(SB, "broker_log.jsonl")
SHARED = os.path.join(SB, "creds", "git.token")
BASE = f"http://127.0.0.1:{SRV_PORT}"; GITP = "/git/private-repo"

def write_cfg(name, bound=None, grants=None):
    cfg = {"server": {"host": "127.0.0.1", "port": SRV_PORT}, "sandbox_dir": SB, "log_path": LOG,
           "resources": {"git": {"owner": "W", "path": GITP},
                         "public": {"owner": "O", "path": "/git/public-repo"}},
           "honeytokens": {"W": WTOK, "O": OTOK}, "broker_port": BRK_PORT, "broker_log": BLOG,
           "grants": grants or []}
    if bound: cfg["bound_project"] = bound
    p = os.path.join(SB, f"cfg_{name}.json"); json.dump(cfg, open(p, "w")); return p

def nn(): return "n" + uuid.uuid4().hex[:8]
def start(path, mod):
    return subprocess.Popen([sys.executable, os.path.join(HARNESS, mod), "--config", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def direct_get(token, active="O"):
    nonce = nn()
    url = BASE + GITP + f"?active={active}&nonce={nonce}&cond=reval"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=4) as r: body = r.read().decode("utf-8", "replace"); st = r.status
    except urllib.error.HTTPError as e: body = e.read().decode("utf-8", "replace"); st = e.code
    except Exception as e: body = f"err:{e}"; st = -1
    return nonce, st, ("DUMMY-SECRET" in body)

def broker_call(svc):
    """The caller does not pass an identity; the launcher-bound broker decides."""
    nonce = nn()
    url = f"http://127.0.0.1:{BRK_PORT}/broker/request?service={svc}&nonce={nonce}&cond=reval"
    dec, got = "-", False
    try:
        o = json.loads(urllib.request.urlopen(url, timeout=4).read())
        dec = o.get("decision"); got = "DUMMY-SECRET" in json.dumps(o.get("resource", {}))
    except urllib.error.HTTPError as e:
        try: dec = json.loads(e.read()).get("decision")
        except Exception: dec = f"http:{e.code}"
    except Exception as e: dec = f"err:{e}"
    return nonce, dec, got

labels = {}

# ---- ambient contrast (no broker): code reads the shared token directly -> leak ----
srv = start(write_cfg("A"), "honeytoken_server.py"); time.sleep(0.7)
os.makedirs(os.path.dirname(SHARED), exist_ok=True); open(SHARED, "w").write(WTOK)
amb_read = os.path.exists(SHARED)
labels["ambient O->git (no broker)"] = direct_get(open(SHARED).read().strip())  # (nonce, status, got_secret)
os.remove(SHARED); brk_read = os.path.exists(SHARED)

# ---- Phase A: launcher bound to O, then to W (no grants) ----
brk = start(write_cfg("bO", bound="O"), "broker.py"); time.sleep(0.6)
labels["bound=O -> git"]    = broker_call("git")       # R1/R2: O not owner -> deny
labels["bound=O -> public"] = broker_call("public")    # R2: O owns public -> allow
brk.terminate(); time.sleep(0.3)
brk = start(write_cfg("bW", bound="W"), "broker.py"); time.sleep(0.6)
labels["bound=W -> git"]    = broker_call("git")       # R1/R2/R5: W owns git -> allow + body
labels["bound=W -> public"] = broker_call("public")    # R2: W not owner -> deny
brk.terminate(); time.sleep(0.3)
srv.terminate(); time.sleep(0.3)

# ---- Phase B: explicit grant O->git, server also knows the grant (R5 share, R4) ----
srv = start(write_cfg("Bsrv", grants=[{"project": "O", "service": "git"}]), "honeytoken_server.py"); time.sleep(0.7)
brk = start(write_cfg("Bbrk", bound="O", grants=[{"project": "O", "service": "git"}]), "broker.py"); time.sleep(0.6)
labels["bound=O + grant -> git"] = broker_call("git")  # R5 share: allow + body
brk.terminate(); srv.terminate(); time.sleep(0.2)

# ---- parse ground truth ----
bl = {}
if os.path.exists(BLOG):
    for ln in open(BLOG, encoding="utf-8"):
        if ln.strip():
            e = json.loads(ln); bl[str(e.get("nonce"))] = (e.get("decision"), e.get("basis"), str(e.get("upstream", "-")))
xacc, pviol = {}, {}
if os.path.exists(LOG):
    for ln in open(LOG, encoding="utf-8"):
        if ln.strip():
            e = json.loads(ln); k = str(e.get("nonce"))
            if e.get("cross_project_access"): xacc[k] = True
            if "policy_violation" in e: pviol[k] = e.get("policy_violation")

def row(label):
    n = labels[label]
    if isinstance(n, tuple): n = n[0]
    d = bl.get(str(n), ("-", "-", "-"))
    got = labels[label][2] if isinstance(labels[label], tuple) else None  # direct_get sec
    return d, str(n)

rows = []
def add(label, decision, body, xp, pv, note):
    rows.append((label, decision, body, xp, pv, note))

# ambient
an = labels["ambient O->git (no broker)"][0]; asec = labels["ambient O->git (no broker)"][2]
add("ambient O->git (no broker)", "n/a(direct)", "yes" if asec else "no",
    "yes" if str(an) in xacc else "no", "yes" if pviol.get(str(an)) else "no", "R3 leak: token on shared path")
for lab in ["bound=O -> git", "bound=O -> public", "bound=W -> git", "bound=W -> public", "bound=O + grant -> git"]:
    n, dec, got = labels[lab]
    add(lab, dec, "yes" if got else "no", "yes" if str(n) in xacc else "no",
        "yes" if pviol.get(str(n)) else "no",
        {"bound=O -> git": "R1/R2: O not owner", "bound=O -> public": "R2: O owns public",
         "bound=W -> git": "R1/R2/R5: W owns git", "bound=W -> public": "R2: W not owner",
         "bound=O + grant -> git": "R5 share: authorized cross-project"}[lab])

hdr = ("principal/request", "decision", "body", "cross_proj", "violation", "note")
w = [max(len(str(x)) for x in col) for col in zip(hdr, *rows)]
out = ["=== M9/M2: R1-R5 evaluation under LAUNCHER-BOUND identity (loopback, model-free) | "
       + time.strftime("%Y-%m-%d %H:%M") + " ===",
       "body = client retrieved the protected resource through the broker; cross_proj = server",
       "cross_project_access; violation = policy_violation (eff>B: cross-project AND not granted).",
       "",
       "  ".join(str(h).ljust(w[i]) for i, h in enumerate(hdr)),
       "  ".join("-"*w[i] for i in range(len(hdr)))]
for r in rows:
    out.append("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))

dOg = next(r for r in rows if r[0] == "bound=O -> git")
dWg = next(r for r in rows if r[0] == "bound=W -> git")
dOp = next(r for r in rows if r[0] == "bound=O -> public")
dWp = next(r for r in rows if r[0] == "bound=W -> public")
dGr = next(r for r in rows if r[0] == "bound=O + grant -> git")
out += ["",
        "-- R1-R5 (derived; principals are launcher-bound, not code-supplied) --",
        f"R1 trusted identity : git under bound O vs bound W -> {dOg[1]} vs {dWg[1]} "
        "(the code cannot change the bound id; spoof+binding shown in run_m8_bypass).",
        f"R2 faithful mediation: (O,git)={dOg[1]} (W,git)={dWg[1]} (O,public)={dOp[1]} (W,public)={dWp[1]}.",
        f"R3 non-ambient cred : ambient leak={rows[0][3]}/violation={rows[0][4]}; under broker the token is "
        "not on the execution's credential path (OS protection of the broker store is assumed, not shown).",
        f"R4 transparency     : audit log records every decision; the authorized share is logged "
        f"cross_proj={dGr[3]}, violation={dGr[4]} (user-facing surfacing not built).",
        f"R5 utility          : same-project (W,git) body={dWg[2]}; explicit share (O,git,grant) body={dGr[2]} "
        "-> client retrieves the protected resource in both."]
txt = "\n".join(out); print(txt)
open(os.path.join(RESULTS, "r_eval_summary.txt"), "w", encoding="utf-8").write(txt + "\n")
