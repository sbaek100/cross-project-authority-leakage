#!/usr/bin/env python3
"""Aggregate the server access log into the result tables the paper needs.

Reads results/access_log.jsonl and reports, per (scenario, condition, trigger):
  - trials observed (distinct trial ids)
  - trials with a cross-project access event (valid owner-credential used to
    reach that owner's resource while a different project was active)
  - the resulting access rate (numerator/denominator)

Deduplicates by (trial, nonce) and ignores rows with no nonce, so prefetch /
redirect / logger self-requests do not inflate counts. Prints a table that
maps onto RQ1 (prevalence) and the C0–C3 causal table.
"""
import argparse, json, collections

def load_config(p):
    with open(p, encoding="utf-8") as f: return json.load(f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.json")
    args = ap.parse_args()
    cfg = load_config(args.config)
    rows = []
    try:
        with open(cfg["log_path"], encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        print("no log yet:", cfg["log_path"]); return

    # cell -> set(trial ids seen), set(trial ids with cross-project access)
    seen = collections.defaultdict(set)
    hit = collections.defaultdict(set)
    for r in rows:
        if not r.get("nonce"):
            continue
        cell = (r.get("scn", "?"), r.get("cond", "?"), r.get("trig", "?"))
        tid = (r.get("trial", "?"), r.get("nonce"))
        seen[cell].add(r.get("trial", "?"))
        if r.get("cross_project_access"):
            hit[cell].add(r.get("trial", "?"))

    print(f"{'scn':<4}{'cond':<6}{'trig':<8}{'xproj/total':<14}{'rate'}")
    print("-" * 44)
    for cell in sorted(seen):
        scn, cond, trig = cell
        tot = len(seen[cell]); h = len(hit[cell])
        rate = f"{h/tot:.2f}" if tot else "-"
        print(f"{scn:<4}{cond:<6}{trig:<8}{f'{h}/{tot}':<14}{rate}")
    print("\nNote: denominator = distinct trials with a nonce in that cell. "
          "0/N is not proof of containment; report observation limits (see protocol).")

if __name__ == "__main__":
    main()
