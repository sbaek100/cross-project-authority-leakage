#!/usr/bin/env python3
"""Fake CLI that models how a real command-line client caches a token in the
home/sandbox directory (the substrate state), then uses it to reach a resource.

This stands in for `gh auth login` / a cloud CLI *without* touching any real
service or credential. `login` writes a researcher-generated honeytoken to a
sandbox file; `fetch` reads that file and calls the loopback dummy server.

Purpose in the study: `login` is run while "project W" is active to create the
cached-credential substrate state; `fetch` (or the probe) is exercised while
"project O" is active, to test whether O can use W's cached token.
"""
import argparse, json, os, urllib.request

def load_config(p):
    with open(p, encoding="utf-8") as f: return json.load(f)

def token_path(cfg, service):
    d = os.path.join(os.path.expanduser(cfg["sandbox_dir"]), "creds")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"{service}.token")

def cmd_login(cfg, args):
    tok = cfg["honeytokens"][args.as_project]
    p = token_path(cfg, args.service)
    with open(p, "w", encoding="utf-8") as f:
        f.write(tok)
    print(f"[fake_cli] cached honeytoken for project {args.as_project} at {p}")
    print("[fake_cli] (this is a meaningless honeytoken string, not a real credential)")

def cmd_fetch(cfg, args):
    p = token_path(cfg, args.service)
    if not os.path.exists(p):
        print(f"[fake_cli] no cached token at {p} (login first)"); return
    tok = open(p, encoding="utf-8").read().strip()
    res = cfg["resources"][args.service]
    s = cfg["server"]
    q = (f"?trial={args.trial}&cond={args.cond}&trig={args.trig}"
         f"&scn={args.scn}&nonce={args.nonce}&active={args.active}")
    url = f"http://{s['host']}:{s['port']}{res['path']}{q}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(f"[fake_cli] {r.status} {r.read().decode('utf-8','replace')}")
    except urllib.error.HTTPError as e:
        print(f"[fake_cli] {e.code} {e.read().decode('utf-8','replace')}")

def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config.json")
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pl = sub.add_parser("login", parents=[common]); pl.add_argument("--service", required=True)
    pl.add_argument("--as", dest="as_project", required=True, choices=["W", "O"])
    pf = sub.add_parser("fetch", parents=[common]); pf.add_argument("--service", required=True)
    for p in (pf,):
        p.add_argument("--trial", default="t0"); p.add_argument("--cond", default="C1")
        p.add_argument("--trig", default="direct"); p.add_argument("--scn", default="1")
        p.add_argument("--nonce", default="n0"); p.add_argument("--active", default="O")
    args = ap.parse_args()
    cfg = load_config(args.config)
    {"login": cmd_login, "fetch": cmd_fetch}[args.cmd](cfg, args)

if __name__ == "__main__":
    main()
