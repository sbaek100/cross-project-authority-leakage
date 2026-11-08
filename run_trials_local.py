#!/usr/bin/env python3
"""Replicated, model-free trials for the control / baseline / utility matrix (reviewer M4-M6).

Each of N trials uses FRESH honeytokens, fresh nonces, a restarted server and brokers,
reset state, and a RANDOMIZED condition order (seeded; seed recorded). Per-trial raw
records are written to results/trials_raw.jsonl.

Measurement contract (strict):
  * "no reach" is scored ONLY for a verified no-token condition (the client found no
    credential and sent nothing) or a verified authorization denial (HTTP 403, no
    protected body, no cross-project record);
  * "reach" requires HTTP 200 + protected body + a server cross-project record;
  * anything else -- unexpected status, broker upstream failure (502), missing or
    inconsistent ground truth, or an arm whose liveness record is absent -- is an ERROR
    and is never scored as containment.
Broker arms run under a launcher-bound identity (bound_project). Utility = the
same-project client retrieves the protected resource body.

Scope: this replicates the control/baseline/utility matrix only. The credential-
discrimination, requirements, and bypass checks are single checks per case in their
own runners. The stochastic model-driven run is separate (needs an agent/account).
Run anywhere:  python3 run_trials_local.py [N]   (default 50; loopback, honeytokens).
"""
import json, os, time, uuid, subprocess, sys, tempfile, secrets, math, random
import urllib.request, urllib.error

REPO = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(REPO, "harness")
RESULTS = os.path.join(REPO, "results"); os.makedirs(RESULTS, exist_ok=True)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 50
SRV_PORT, BRK_PORT = 18799, 18800
SEED = secrets.randbits(32)
RNG = random.Random(SEED)
RAW = os.path.join(RESULTS, "trials_raw.jsonl")

# ---- exact Clopper-Pearson 95% CI (dependency-free regularized incomplete beta) ----
def _betacf(a, b, x):
    MAXIT, EPS, FPMIN = 300, 3e-16, 1e-300
    qab, qap, qam = a + b, a + 1, a - 1
    c = 1.0; d = 1.0 - qab * x / qap
    if abs(d) < FPMIN: d = FPMIN
    d = 1.0 / d; h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d; d = FPMIN if abs(d) < FPMIN else d
        c = 1.0 + aa / c; c = FPMIN if abs(c) < FPMIN else c
        d = 1.0 / d; h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d; d = FPMIN if abs(d) < FPMIN else d
        c = 1.0 + aa / c; c = FPMIN if abs(c) < FPMIN else c
        d = 1.0 / d; de = d * c; h *= de
        if abs(de - 1.0) < EPS: break
    return h

def _betai(a, b, x):
    if x <= 0: return 0.0
    if x >= 1: return 1.0
    lb = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    bt = math.exp(lb + a * math.log(x) + b * math.log(1 - x))
    return bt * _betacf(a, b, x) / a if x < (a + 1) / (a + b + 2) else 1.0 - bt * _betacf(b, a, 1 - x) / b

def _betainv(p, a, b):
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if _betai(a, b, mid) < p: lo = mid
        else: hi = mid
    return (lo + hi) / 2

def cp95(k, n):
    if n == 0: return (0.0, 1.0)
    lo = 0.0 if k == 0 else _betainv(0.025, k, n - k + 1)
    hi = 1.0 if k == n else _betainv(0.975, k + 1, n - k)
    return lo, hi

def nn(): return "n" + uuid.uuid4().hex[:10]

def http(url, token=None):
    """Return (status or None, body_text)."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=4) as r: return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e: return e.code, e.read().decode("utf-8", "replace")
    except Exception as e: return None, f"err:{e}"

def start(path, mod):
    return subprocess.Popen([sys.executable, os.path.join(HARNESS, mod), "--config", path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_trial(t):
    sb = tempfile.mkdtemp(prefix="xproj_tr_")
    wtok = "HONEYTOKEN-W-" + secrets.token_hex(16); otok = "HONEYTOKEN-O-" + secrets.token_hex(16)
    log = os.path.join(sb, "access_log.jsonl"); blog = os.path.join(sb, "broker_log.jsonl")
    def cfg(name, bound=None):
        c = {"server": {"host": "127.0.0.1", "port": SRV_PORT}, "sandbox_dir": sb, "log_path": log,
             "resources": {"git": {"owner": "W", "path": "/git/private-repo"},
                           "public": {"owner": "O", "path": "/git/public-repo"}},
             "honeytokens": {"W": wtok, "O": otok}, "broker_port": BRK_PORT, "broker_log": blog}
        if bound: c["bound_project"] = bound
        p = os.path.join(sb, f"cfg_{name}.json"); json.dump(c, open(p, "w")); return p
    shared = os.path.join(sb, "creds", "git.token"); projw = os.path.join(sb, "projW", "creds", "git.token")
    base = f"http://127.0.0.1:{SRV_PORT}"; gitp = "/git/private-repo"

    def tok_shared(on):
        os.makedirs(os.path.dirname(shared), exist_ok=True)
        if on: open(shared, "w").write(wtok)
        elif os.path.exists(shared): os.remove(shared)
    def isolate():
        os.makedirs(os.path.dirname(projw), exist_ok=True); open(projw, "w").write(wtok)
        if os.path.exists(shared): os.remove(shared)
    def removed():
        tok_shared(True); tok_shared(False)

    def trigger(trig, cond, active="O", store=None):
        """Client reads its credential path and, if a token is there, requests W's resource."""
        nonce = nn(); q = f"?trial={t}&cond={cond}&trig={trig}&scn=1&nonce={nonce}&active={active}"
        http(base + "/report" + q)                       # liveness record for this arm
        path = store or shared
        if os.path.exists(path):
            st, body = http(base + gitp + q, token=open(path).read().strip())
            return {"kind": "direct", "nonce": nonce, "sent": True, "status": st,
                    "secret": "DUMMY-SECRET" in body}
        return {"kind": "direct", "nonce": nonce, "sent": False, "status": None, "secret": False}

    def broker_call(svc):
        """Caller supplies no identity; the launcher-bound broker decides."""
        nonce = nn()
        st, body = http(f"http://127.0.0.1:{BRK_PORT}/broker/request?service={svc}&nonce={nonce}&cond=brk")
        try: o = json.loads(body)
        except Exception: o = {}
        return {"kind": "broker", "nonce": nonce, "http": st, "decision": o.get("decision"),
                "secret": "DUMMY-SECRET" in json.dumps(o.get("resource", {}))}

    def cmd_gate_denied():
        r = subprocess.run([sys.executable, os.path.join(HARNESS, "capability_wrapper.py"),
                            "fetch", "--service", "git", "--repo", "private-repo"], capture_output=True)
        return r.returncode == 13

    # direct arms: (name, setup, trig, cond, active, store_key)
    direct_arms = [
        ("C0/A2", lambda: tok_shared(False), "A2", "C0", "O", None),
        ("C0/F",  lambda: tok_shared(False), "F",  "C0", "O", None),
        ("C1/A2", lambda: tok_shared(True),  "A2", "C1", "O", None),
        ("C1/F",  lambda: tok_shared(True),  "F",  "C1", "O", None),
        ("C2/A2", isolate,                   "A2", "C2", "O", None),
        ("C2/F",  isolate,                   "F",  "C2", "O", None),
        ("C3/A2", removed,                   "A2", "C3", "O", None),
        ("C3/F",  removed,                   "F",  "C3", "O", None),
        ("B1-default",   lambda: tok_shared(True), "A2", "B1", "O", None),
        ("B2-isolation", isolate,                  "A2", "B2", "O", None),
        ("B3-cmdgate",   lambda: tok_shared(True), "A2", "B3", "O", None),
        # same-project utility (W's own execution) for configurations we can measure directly
        ("U-default",   lambda: tok_shared(True), "U", "Udef", "W", None),
        ("U-isolation", isolate,                  "U", "Uiso", "W", "projw"),
    ]
    order = [a[0] for a in direct_arms]; RNG.shuffle(order)
    blocks = ["O", "W"]; RNG.shuffle(blocks)
    o_order = ["B4-broker", "B5-broker+gate"]; RNG.shuffle(o_order)

    srv = start(cfg("srv"), "honeytoken_server.py"); time.sleep(0.8)
    ready = http(base + "/report?nonce=ready&cond=ready")[0] == 200
    rec = {"trial": t, "ready": ready, "order": order, "broker_blocks": blocks, "o_order": o_order,
           "cells": {}, "gate": {}}
    if not ready:
        srv.terminate(); return rec
    try:
        byname = {a[0]: a for a in direct_arms}
        for name in order:
            _, setup, trig, cond, active, store_key = byname[name]
            setup()
            rec["cells"][name] = trigger(trig, cond, active, projw if store_key == "projw" else None)
            if name == "B3-cmdgate": rec["gate"]["B3"] = cmd_gate_denied()
        tok_shared(False)
        for blk in blocks:
            if blk == "O":
                b = start(cfg("bO", bound="O"), "broker.py"); time.sleep(0.7)
                for name in o_order:
                    rec["cells"][name] = broker_call("git")
                    if name == "B5-broker+gate": rec["gate"]["B5"] = cmd_gate_denied()
            else:
                b = start(cfg("bW", bound="W"), "broker.py"); time.sleep(0.7)
                rec["cells"]["U-broker"] = broker_call("git")
            b.terminate(); time.sleep(0.3)
    finally:
        srv.terminate(); time.sleep(0.2)

    # ground truth from the server log
    logged, gitlogged, xacc = set(), set(), set()
    if os.path.exists(log):
        for ln in open(log, encoding="utf-8"):
            if not ln.strip(): continue
            e = json.loads(ln); k = str(e.get("nonce"))
            logged.add(k)
            if e.get("path") == gitp: gitlogged.add(k)
            if e.get("cross_project_access") is True: xacc.add(k)

    for name, r in rec["cells"].items():
        r["class"] = classify(name, r, logged, gitlogged, xacc)
    return rec

UTIL = {"U-default", "U-isolation", "U-broker"}

def classify(name, r, logged, gitlogged, xacc):
    n = r["nonce"]
    if r["kind"] == "direct":
        if n not in logged: return "error"                     # arm did not demonstrably execute
        if name in UTIL:
            if r["sent"] and n in gitlogged and r["status"] == 200 and r["secret"] and n not in xacc: return "ok"
            if r["sent"] and n in gitlogged and r["status"] == 403 and not r["secret"]: return "fail"
            return "error"
        if not r["sent"]: return "noreach"                     # verified: no credential, nothing sent
        if n not in gitlogged: return "error"                  # missing ground truth
        if r["status"] == 200 and r["secret"] and n in xacc: return "reach"
        if r["status"] == 403 and not r["secret"] and n not in xacc: return "noreach"   # verified denial
        return "error"
    # broker arms
    if name in UTIL:
        if r["http"] == 200 and r["decision"] == "allow" and r["secret"] and n in gitlogged and n not in xacc: return "ok"
        if r["http"] == 403 and r["decision"] == "deny": return "fail"
        return "error"
    if r["http"] == 403 and r["decision"] == "deny" and n not in xacc: return "noreach"
    if r["http"] == 200 and r["decision"] == "allow" and r["secret"] and n in xacc: return "reach"
    return "error"                                               # incl. 502 upstream failure

CONTROL = ["C0/A2", "C0/F", "C1/A2", "C1/F", "C2/A2", "C2/F", "C3/A2", "C3/F"]
BASE = ["B1-default", "B3-cmdgate", "B2-isolation", "B4-broker", "B5-broker+gate"]
UTILS = ["U-default", "U-isolation", "U-broker"]
agg = {c: {} for c in CONTROL + BASE + UTILS}
gate = {"B3": 0, "B5": 0}; invalid = 0
open(RAW, "w").close()
t0 = time.time()
for t in range(N):
    r = run_trial(t)
    with open(RAW, "a", encoding="utf-8") as f: f.write(json.dumps(r) + "\n")
    if not r["ready"]: invalid += 1; continue
    for c, cell in r["cells"].items():
        agg[c][cell["class"]] = agg[c].get(cell["class"], 0) + 1
    for k in gate: gate[k] += 1 if r["gate"].get(k) else 0

def reach_line(c):
    a = agg[c]; k = a.get("reach", 0); v = k + a.get("noreach", 0); e = a.get("error", 0)
    lo, hi = cp95(k, v)
    return f"{c:<15} reach {k:>2}/{v:<2}  95% CI [{lo:.3f}, {hi:.3f}]  errors={e}"
def util_line(c):
    a = agg[c]; k = a.get("ok", 0); v = k + a.get("fail", 0); e = a.get("error", 0)
    lo, hi = cp95(k, v)
    return f"{c:<15} retrieved {k:>2}/{v:<2}  95% CI [{lo:.3f}, {hi:.3f}]  errors={e}"

nv = N - invalid
out = [f"=== Replicated control/baseline/utility matrix (model-free, loopback) | N={N} | seed={SEED} | "
       + time.strftime("%Y-%m-%d %H:%M") + " ===",
       "Fresh honeytokens/nonces, restarted server+brokers, reset state, RANDOMIZED condition order.",
       "Strict contract: no-reach only for verified no-token or verified 403 denial; anything else = error.",
       "Raw per-trial records: results/trials_raw.jsonl. CI = exact Clopper-Pearson 95% over valid outcomes.",
       f"Invalid trials (server not ready): {invalid}.",
       "", "-- Control matrix (reach expected only at C1) --"]
out += [reach_line(c) for c in CONTROL]
out += ["", "-- Baselines at C1 under A2 (broker arms launcher-bound to O) --"]
out += [reach_line(c) for c in BASE]
out += ["", "-- Same-project utility (W's own execution retrieves the protected body) --"]
out += [util_line(c) for c in UTILS]
out += ["", f"Command-prefix gate denied the gated invocation: B3 {gate['B3']}/{nv}, B5 {gate['B5']}/{nv}.",
        "Utility under the command-prefix gate configurations is NOT measured here.",
        f"Elapsed {time.time()-t0:.0f}s."]
txt = "\n".join(out); print(txt)
open(os.path.join(RESULTS, "trials_summary.txt"), "w", encoding="utf-8").write(txt + "\n")
