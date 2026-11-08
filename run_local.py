#!/usr/bin/env python3
"""Local, model-free, account-free reproducer for EXP-1 (broker defense, sec3) +
EXP-2 (baselines, sec4.2). Mirrors run_defense.ps1's arms but WITHOUT the Codex
sandbox wrapper, because the broker/substrate result is agent-independent.

Run anywhere:   python3 run_local.py
Honeytokens are random throwaway strings generated per run; all traffic is
loopback; no real service, credential, account, or model is involved. Writes
results/defense_summary_local.txt and prints the table.
"""
import json, os, time, uuid, subprocess, sys, tempfile, secrets
import urllib.request, urllib.error

REPO = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(REPO, "harness")
RESULTS = os.path.join(REPO, "results"); os.makedirs(RESULTS, exist_ok=True)

# throwaway, loopback-only runtime config (self-contained; no real creds/accounts)
SBDIR = tempfile.mkdtemp(prefix="xproj_local_sb_")
SRV_PORT, BRK_PORT = 18799, 18800
WTOK = "HONEYTOKEN-W-" + secrets.token_hex(16)
OTOK = "HONEYTOKEN-O-" + secrets.token_hex(16)
LOG  = os.path.join(SBDIR, "access_log.jsonl")
BLOG = os.path.join(SBDIR, "broker_log.jsonl")
CFG = {
    "server": {"host": "127.0.0.1", "port": SRV_PORT},
    "sandbox_dir": SBDIR,
    "log_path": LOG,
    "resources": {"git": {"owner": "W", "path": "/git/private-repo"},
                  "public": {"owner": "O", "path": "/git/public-repo"}},
    "honeytokens": {"W": WTOK, "O": OTOK},
    "broker_port": BRK_PORT,
    "broker_log": BLOG,
}
CFG_PATH = os.path.join(SBDIR, "config.json")
json.dump(CFG, open(CFG_PATH, "w"))

SHARED = os.path.join(SBDIR, "creds", "git.token")           # shared substrate path (O's probe reads this)
PROJW  = os.path.join(SBDIR, "projW", "creds", "git.token")  # per-project isolated store (O cannot read)
BASEURL = f"http://127.0.0.1:{SRV_PORT}"


def tok_shared(on):
    os.makedirs(os.path.dirname(SHARED), exist_ok=True)
    if on: open(SHARED, "w").write(WTOK)
    elif os.path.exists(SHARED): os.remove(SHARED)

def isolate():
    os.makedirs(os.path.dirname(PROJW), exist_ok=True)
    open(PROJW, "w").write(WTOK)                      # W authenticated into its own per-project store
    if os.path.exists(SHARED): os.remove(SHARED)      # shared path empty -> O cannot see W's token

def nn(): return "n" + uuid.uuid4().hex[:6]

def _get(url, token=None):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=4) as r: return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception: return None

def probe_direct(cond, nonce):     # A2: read shared token directly, reach server as active=O
    found = os.path.exists(SHARED)
    q = f"?trial=local&cond={cond}&trig=A2&scn=1&nonce={nonce}&active=O"
    _get(BASEURL + "/report" + q)
    if found:
        _get(BASEURL + CFG["resources"]["git"]["path"] + q, token=open(SHARED).read().strip())
    return {"token_read": found, "broker_decision": ""}

def probe_broker(cond, nonce, project):  # defense: no direct token use; ask broker with injected project id
    direct = os.path.exists(SHARED)
    url = f"http://127.0.0.1:{BRK_PORT}/broker/request?project={project}&service=git&nonce={nonce}&cond={cond}"
    dec = "NO_RUN"
    try: dec = json.loads(urllib.request.urlopen(url, timeout=4).read()).get("decision")
    except urllib.error.HTTPError as e:
        try: dec = json.loads(e.read()).get("decision")
        except Exception: dec = f"http:{e.code}"
    except Exception as e: dec = f"err:{e}"
    return {"token_read": direct, "broker_decision": dec}

def cmd_gate_denied():   # CapScope-style: the gated command for W's PRIVATE repo must be denied (exit 13)
    r = subprocess.run([sys.executable, os.path.join(HARNESS, "capability_wrapper.py"),
                        "fetch", "--service", "git", "--repo", "private-repo"], capture_output=True)
    return r.returncode == 13

def main():
    srv = subprocess.Popen([sys.executable, os.path.join(HARNESS, "honeytoken_server.py"), "--config", CFG_PATH],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    brk = subprocess.Popen([sys.executable, os.path.join(HARNESS, "broker.py"), "--config", CFG_PATH],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    rows = []
    def arm(label, setup, probe, project="O", cmd_denied="n/a"):
        setup()
        if cmd_denied == "GATE": cmd_denied = cmd_gate_denied()
        nonce = nn()
        r = probe(label, nonce, project) if probe is probe_broker else probe(label, nonce)
        rows.append({"arm": label, "project": project, "nonce": nonce, "token_read": r["token_read"],
                     "broker_decision": r["broker_decision"], "cmd_denied": cmd_denied})
    try:
        arm("B1-default",         lambda: tok_shared(True),  probe_direct, "O")
        arm("B2-isolation",       isolate,                   probe_direct, "O")
        arm("B3-capscope",        lambda: tok_shared(True),  probe_direct, "O", "GATE")
        arm("B4-broker",          lambda: tok_shared(False), probe_broker, "O")
        arm("B5-broker+capscope", lambda: tok_shared(False), probe_broker, "O", "GATE")
        arm("U-broker-utility",   lambda: tok_shared(False), probe_broker, "W")
        arm("C0-notoken",         lambda: tok_shared(False), probe_direct, "O")
        arm("C3-removed",         lambda: (tok_shared(True), tok_shared(False)), probe_direct, "O")
        time.sleep(0.6)
    finally:
        srv.terminate(); brk.terminate()

    reach, bup = {}, {}
    if os.path.exists(LOG):
        for ln in open(LOG, encoding="utf-8"):
            if ln.strip():
                e = json.loads(ln)
                if e.get("cross_project_access") is True: reach[str(e.get("nonce"))] = True
    if os.path.exists(BLOG):
        for ln in open(BLOG, encoding="utf-8"):
            if ln.strip():
                e = json.loads(ln); bup[str(e.get("nonce"))] = f"{e.get('decision')}/{e.get('upstream','-')}"
    for r in rows:
        r["resource_reach"] = bool(reach.get(r["nonce"], False))
        r["broker_upstream"] = bup.get(r["nonce"], "")

    hdr = ["arm", "project", "resource_reach", "token_read", "broker_decision", "cmd_denied", "broker_upstream"]
    w = {h: max(len(h), *(len(str(r.get(h, ""))) for r in rows)) for h in hdr}
    out = ["=== EXP-1 broker (sec3) + EXP-2 baselines (sec4.2) | LOCAL model-free run | " + time.strftime("%Y-%m-%d %H:%M") + " ===",
           "resource_reach = eff_O(W) > B_O confirmed by honeytoken server (cross_project_access). Honeytokens + loopback only.",
           "  ".join(h.ljust(w[h]) for h in hdr),
           "  ".join("-" * w[h] for h in hdr)]
    out += ["  ".join(str(r.get(h, "")).ljust(w[h]) for h in hdr) for r in rows]
    out += ["",
            "Read guide:",
            " B1-default   : reach=True  => product default leaks cross-project (baseline).",
            " B2-isolation : reach=False => per-project store blocks it (W token not on shared substrate).",
            " B3-capscope  : cmd_denied=True BUT reach=True => command gate != substrate authority.",
            " B4-broker    : reach=False, decision=deny, token_read=False => broker closes the leak (sec3).",
            " U-utility    : decision=allow, upstream=200 => same-project use still works (R5 utility preserved).",
            " C0 / C3      : reach=False => causal control (leak tied to W's authentication state).",
            "Note: 0 reach is not proof of complete mediation; only the git resource path is demonstrated."]
    text = "\n".join(out)
    print(text)
    open(os.path.join(RESULTS, "defense_summary_local.txt"), "w", encoding="utf-8").write(text + "\n")

if __name__ == "__main__":
    main()
