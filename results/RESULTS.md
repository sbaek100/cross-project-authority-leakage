# Experimental Results Index

All experiments use loopback-only resources and researcher-generated honeytokens
(meaningless random strings, never real credentials) in an isolated, single-user
environment. Section numbers refer to the current manuscript (`paper/main.tex`).

Terminology used throughout:
- **reach** = `eff_O(W) > B_O`: an operation while project O is active obtains W's
  protected resource with W's credential, in violation of policy. Ground truth is the
  resource server's `cross_project_access` record; `policy_violation` additionally
  excludes accesses covered by an explicit grant.
- **C3 = removed (deleted)**: W's cached credential is deleted. This is distinct from
  **server-side revocation** (a presented credential rejected by the server), which is
  tested only in `m2m3_summary.txt`.

## Provenance of every summary

| Summary | Runner | Execution context | Runs | Implementation |
|---|---|---|---|---|
| `trials_summary.txt`, `trials_raw.jsonl` | `run_trials_local.py` | model-free harness | 50 per cell, randomized order | current: strict classifier, launcher-bound broker, body-returning broker |
| `m2m3_summary.txt` | `run_m2m3_local.py` | model-free harness | 1 per case | current server (ownership + revocation) |
| `r_eval_summary.txt` | `run_r_eval_local.py` | model-free harness | 1 per case | current: launcher-bound, body-returning broker; policy_violation |
| `m8_bypass_summary.txt` | `run_m8_bypass_local.py` | model-free harness | 1 per case | current broker (bound_project) |
| `defense_summary_local.txt` | `run_local.py` | model-free harness | 1 per arm | mirror of the earlier design: broker identity supplied as a query parameter |
| `codex_a2_summary.txt` | `run_auto.ps1` | native coding agent (Codex CLI) under its sandbox profiles | 1 per row | earlier harness; uses old notation (see below) |
| `defense_summary_codex_sandbox.txt` | `run_defense.ps1` | probe under the agent's `workspace-write` sandbox | 1 per arm | earlier broker (query-parameter identity, decision-only response) |
| `f_direct_summary.txt` | `run_f_direct.ps1` | release-build fixture `fixtures/projF` | 3 per condition | earlier harness |
| `f_model_autonomy_summary.txt` | `run_f.ps1` (prompt inside) | native agent drives the build, one model, one prompt | 5 per condition (C0, C1, C3) | earlier harness |

The agent-sandbox summaries predate the launcher-bound, body-returning broker. They
corroborate the substrate effect, not the current prototype.

## Sec. 5.2 — causality controls (Table 1)
- `trials_summary.txt`: C1/A2 and C1/F reach 50/50 (exact 95% CI [0.929, 1.000]);
  C0, C2, C3 (A2 and F) reach 0/50 ([0.000, 0.071]); 0 errors; 0 invalid trials.
  In this matrix **F is a synthetic credential-use request** that differs from A2 only
  in its provenance label. It is not the end-to-end release build.
- `f_direct_summary.txt`: the release-build fixture reached W at C1 in 3/3 runs, 0/3 at
  C0 and C3. Evidence: `transcripts/fd_C1_1_benign_build.log`,
  `transcripts/f_direct_access_log.jsonl`.
- `codex_a2_summary.txt` (native agent): reach under `workspace` and `read-only`
  profiles (one run each); C0 and C3 no reach.
  - The `danger-full-access` row **exited with an error (exit 1)**. It is an execution
    failure, not containment, and is not used in the paper.
  - The `read-only` row has `token_read=NO_RUN`; the summary does not document a
    blocked workspace write, so the paper makes no write-blocking claim.
  - Old notation in this file: `I_O` = the project bound now written `B_O`; `L1` = the
    inherited-authority leak class (label no longer used).
- `f_model_autonomy_summary.txt`: C1 2/5 (exact 95% CI [0.053, 0.853]), C0 0/5 and C3
  0/5 ([0, 0.522]); 15 runs; no C2 arm. Transcripts are retained only for C1 run 1
  (`transcripts/f_C1_1_model_report.txt`, `transcripts/f_C1_1_model_actions.txt`).
  These are descriptive single-configuration results, not an agent-population rate.

## Sec. 5.2 — what reach measures
- `m2m3_summary.txt`: on W's resource only W's valid token returns the protected body
  (HTTP 200); absent, random, wrong-owner, and server-revoked tokens get 403. Deletion
  (nothing presented) and revocation (presented, rejected) both yield no reach.

## Sec. 5.3 — baselines and utility (Table 3)
- `trials_summary.txt`: reach 50/50 for product default and command-prefix gate; 0/50
  for isolation, broker, broker+gate; broker denies O's execution 50/50; same-project
  retrieval 50/50 for default, isolation, and broker. Utility under the gate
  configurations is **not measured**. The command-prefix gate is an argument-prefix
  allowlist (`harness/capability_wrapper.py`), not CapScope's typed capability system.
- C2 / isolation moves W's token off the lookup path the client reads. It shows absence
  from that path; it does not show that arbitrary code cannot read other files.

## Sec. 5.3 — requirements status
- `r_eval_summary.txt` (launcher-bound): (O,git) deny, (W,git) allow + body,
  (O,public) allow + body, (W,public) deny; explicit grant (O,git) allow + body, logged
  `cross_project_access=yes`, `policy_violation=no`; ambient path: both yes.
- Status reported in the paper: R1 partial, R2 partial, R3 assumed beyond the tested
  path, R4 partial (audit log, no user surfacing), R5 demonstrated.

## Sec. 5.3 — mediation boundary
- `m8_bypass_summary.txt`: token on a readable file or in an environment variable is
  usable without the broker; a broker trusting a code-supplied identity is bypassed;
  identity bound by configuration closes that case. Not tested: inter-process channels,
  access to another execution's broker, protection of configuration and store files.

## Table 2 — static survey
- **Per-product evidence (product, version, platform, date, configuration, sources,
  observation per cell) is to be supplied by the authors.** Until then the survey rests
  on the authors' assessment described in Sec. 5.2.

The agent and model versions, OS, and sandbox/network settings for the native runs are
in `ENVIRONMENT.md`.

## To be supplied by the authors
- Survey evidence (product, version, platform, date, configuration, and the observation
  behind each Table 2 cell) -- kept with the paper, not in this repository.

## Fixtures and logs in this repository
- `fixtures/projA` (untrusted-code probe), `fixtures/projF` (benign release-build fixture).
- `transcripts/` (broker log, release-build log and access log, one model transcript).
