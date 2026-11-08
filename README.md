# Cross-Project Authority Leakage in LLM Coding Agents — artifact

Reproduction artifact for the ICT Express paper *Cross-Project Authority Leakage in LLM
Coding Agents*. On loopback resources with honeytokens, it reproduces a cross-project
credential leak in a coding agent and evaluates a credential-broker policy that removes
it under a confined execution environment.

> This is a **measurement tool**, not an exploit. It never touches a real service,
> credential, or account.

## Safety boundary
- All requests go only to a **loopback (127.0.0.1) dummy resource server** started by the
  researcher; nothing is sent to any external network.
- The only "tokens" are **honeytokens**: meaningless random strings generated per run. No
  code reads an OS keychain, browser cookies, or a real CLI credential store.
- The agent runs use a **dedicated throwaway account** with an isolated agent-home
  directory, one agent at a time, and state is reset between conditions.

## Quick start (model-free; reproduces the deterministic numbers)
```
python3 run_trials_local.py        # control + baseline + utility matrix (N=50)
python3 run_m2m3_local.py          # what "reach" means; removal vs revocation
python3 run_r_eval_local.py        # requirements R1-R5 under a launcher-bound identity
python3 run_m8_bypass_local.py     # broker mediation boundary / bypass channels
```
These use only the Python standard library — no agent, no model, no network beyond
loopback. Each writes a summary under `results/`.

## What reproduces which result
| Run | Output | Paper |
|---|---|---|
| `run_trials_local.py` | `results/trials_summary.txt`, `trials_raw.jsonl` | Table 1 (controls), Table 3 (baselines + utility), §5.2–5.3 |
| `run_m2m3_local.py` | `results/m2m3_summary.txt` | §5.2 (reach = exercised authority; removal vs revocation) |
| `run_r_eval_local.py` | `results/r_eval_summary.txt` | §5.3 (requirements status R1–R5) |
| `run_m8_bypass_local.py` | `results/m8_bypass_summary.txt` | §5.3 (mediation boundary / bypass channels) |
| `run_local.py` | `results/defense_summary_local.txt` | §5.3 (model-free mirror of broker/baselines) |
| `run_auto.ps1`, `run_defense.ps1` | `results/codex_a2_summary.txt`, `defense_summary_codex_sandbox.txt` | §5.2 (A2 under the agent's own sandbox) |
| `run_f.ps1`, `run_f_direct.ps1` | `results/f_model_autonomy_summary.txt`, `f_direct_summary.txt` | §5.2 (benign build: model-driven and deterministic) |

`results/RESULTS.md` is the index: it lists, per summary, the runner, execution context,
run count, and which implementation produced it. `results/ENVIRONMENT.md` records the
host and the dynamically tested agent and versions.

## Agent-driven runs (`*.ps1`, Windows + Codex CLI)
The `.ps1` runners drive the one agent measured dynamically (the **Codex CLI**) through
its own sandbox permission profiles, full-auto, under a dedicated throwaway account with
an isolated `CODEX_HOME`. They require a Windows host with the Codex CLI installed and a
throwaway agent account; see `results/ENVIRONMENT.md` for the versions used. The core
claims are also reproducible model-free with the `run_*_local.py` runners above.

The five-agent static survey in the paper is reported as an anonymized class; only the
agent we also measured dynamically (the Codex CLI) is named. This repository contains the
measurement code and results, not the survey's per-product evidence.

## Layout
- `harness/` — loopback resource server, credential broker, capability wrapper, probe,
  fixtures client, reset/aggregate helpers.
- `fixtures/projA` (untrusted-code probe), `fixtures/projF` (benign release build).
- `run_*_local.py` — model-free runners. `run_*.ps1` — agent-driven runners.
- `results/` — summaries, `trials_raw.jsonl` (per-trial raw records), `RESULTS.md`,
  `ENVIRONMENT.md`.
- `config.example.json` — copy to `config.json` (git-ignored) and set fresh honeytokens.

## Notation
A cross-project violation is written `eff_O(W) > B_O` (project O's realized access to W's
resource exceeds its bound). One result file (`results/codex_a2_summary.txt`) predates
the final manuscript and uses the earlier symbol `I_O` for the same bound; `RESULTS.md`
notes this.

## License
MIT — see `LICENSE`.
