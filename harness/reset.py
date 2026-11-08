#!/usr/bin/env python3
"""Reset state between trials: archive the access log and clear the harness sandbox
(cached honeytokens, canaries). Does NOT touch any real agent home directory unless an
explicit --agent-home-slot path is given (and even then only after confirmation), to
avoid deleting real user data by accident.
"""
import argparse, json, os, shutil, time

def load_config(p):
    with open(p, encoding="utf-8") as f: return json.load(f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--agent-home-slot", default=None,
                    help="OPTIONAL explicit path to a *dedicated test* agent-home slot to "
                         "clear. Never pass a real account's home.")
    ap.add_argument("--real-home", default=None,
                    help="Path the slot must NOT equal (a guard against clearing a real "
                         "agent home). Required with --agent-home-slot.")
    ap.add_argument("--yes", action="store_true", help="skip confirmation")
    args = ap.parse_args()
    cfg = load_config(args.config)

    # archive log
    lp = cfg["log_path"]
    if os.path.exists(lp):
        ts = time.strftime("%Y%m%d-%H%M%S")
        arch = lp + f".{ts}.bak"
        shutil.move(lp, arch)
        print(f"[reset] archived log -> {arch}")

    # clear sandbox (our own dir only)
    sb = os.path.expanduser(cfg["sandbox_dir"])
    if os.path.isdir(sb):
        shutil.rmtree(sb)
        print(f"[reset] cleared sandbox {sb}")
    os.makedirs(sb, exist_ok=True)

    # optional dedicated test agent-home slot
    if args.agent_home_slot:
        slot = os.path.expanduser(args.agent_home_slot)
        if args.real_home and os.path.realpath(slot) == os.path.realpath(os.path.expanduser(args.real_home)):
            print("[reset] REFUSING: that is the real agent home, not a test slot."); return
        if not args.yes:
            print(f"[reset] would clear test slot {slot} -- re-run with --yes to confirm."); return
        if os.path.isdir(slot):
            shutil.rmtree(slot); print(f"[reset] cleared test slot {slot}")
    print("[reset] done")

if __name__ == "__main__":
    main()
