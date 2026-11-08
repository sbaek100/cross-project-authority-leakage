# Experiment environment and versions

Captured from the dedicated throwaway account's agent session metadata and the host.
All agent runs used an isolated `CODEX_HOME` (`C:\Users\USER\codex-test`) on a dedicated
account, one agent at a time, loopback-only resources, honeytokens only.

## Host
- OS: Microsoft Windows 11 Pro, 10.0.26300 (build 26300), x64
- Python (Windows, harness + native runners): 3.10.11
- Python (WSL, model-free runners re-run for the round-2 response): 3.12.3

## Dynamically tested agent (the one coding agent measured dynamically)
Product: **OpenAI Codex CLI** (`originator = codex_exec`), full-auto
(`approval_policy = never`), `network_access = none`, run under its own permission
profiles.

| Phase | Codex CLI | Model | Reasoning | Sandbox profiles used | Working dir |
|---|---|---|---|---|---|
| A2 probe + baselines (initial) | 0.130.0-alpha.5 | gpt-5.5 | (default) / high | read-only; danger-full-access | projA |
| A2 / baselines re-run + benign-build F (model-driven) | 0.167.0 | gpt-6.1-sol | high | read-only; danger-full-access | projA, projF |

Notes:
- The static-survey agents were assessed separately (documentation + shipped-client
  inspection + observed behavior); their products/versions are listed in
  `SURVEY.md` (to be completed by the authors — see RESULTS.md).
- `run_auto.ps1` also exercises the agent's `workspace-write` profile for the A2 probe;
  the `read-only` row has `token_read = NO_RUN`, and the `danger-full-access` A2 row
  exited with an error (exit 1) and is reported as a failure, not containment.
- The two Codex CLI versions reflect an upgrade mid-study (0.130.0-alpha.5 could not
  parse the newer model catalog); the substrate result is identical across both.

## Model-free harness (version-independent)
- `run_trials_local.py`, `run_m2m3_local.py`, `run_r_eval_local.py`,
  `run_m8_bypass_local.py`, `run_local.py`: pure Python standard library, no agent and
  no model. Each trial restarts the loopback server and broker; `run_trials_local.py`
  records its RNG seed and per-trial raw records (`trials_raw.jsonl`).

## Independent review (not part of the measurement)
- Codex CLI 0.167.0, `-s read-only`, `-c model_reasoning_effort="high"`, reading the
  manuscript and this artifact (`codex_review_prompt_v2.txt`).
