# Model card: Before the Breach (IBM track)

Which newly published vulnerabilities will be added to CISA's Known Exploited
Vulnerabilities (KEV) list? We rank the 72,670 vulnerabilities on the 2026 scoreboard and
submit the top 500 (`outputs/top500.csv`).

## Population and labels

- **Backtest folds.** Fold 2024: vulnerabilities published Jan to Sep 2024. Fold 2025: the
  same for 2025. Each is scored with the data known at the end of its publish month (its
  snapshot month; June 2026 has no signal data, so June rows use July).
- **Label.** 1 if the vulnerability was added to KEV after its snapshot month and on or
  before Nov 4 of the fold year, else 0. Rows already on KEV by the end of their snapshot
  month are dropped, as the organisers did for the scoreboard.
- **Sizes.** 2024: 28,839 rows, 27 positives. 2025: 35,281 rows, 48 positives.
  2026: 72,670 rows (the scoreboard), unlabelled.
- **Scoring.** Hits in the top K, where K keeps the benchmark's pick rate
  (500 of 72,670): K = 198 for 2024 and 243 for 2025. Hits in the top 500 are also
  reported. Ties are broken by `cve_id`.
- **Protocol.** Primary: train 2024, test 2025. Time-reversed (robustness only): train
  2025, test 2024. Final model: train 2024 + 2025, score 2026. Nothing was tuned on 2026.
  Every result is the mean over 5 seeds with the min and max.

## Features used (35)

| Group | Columns |
| --- | --- |
| Signals | `epss_pct` (EPSS percentile within the snapshot month), `exploitdb`, `metasploit`, `nuclei`, `poc_github`, `any_exploit_code` |
| Assigner history | `assigner_kev_prior`, `assigner_cves_prior`, `assigner_kev_rate` (as of the snapshot) |
| Severity and CWE | `cvss3_score` and the 8 CVSS 3 metrics (only when the CNA, not NIST, supplied them), `cvss4_score`, `cwe_primary` (rare CWEs become `other`), `n_cwes` |
| Keywords | 11 description flags (`kw_unauthenticated`, `kw_remote_code_execution`, `kw_command_injection`, `kw_pre_auth`, `kw_default_config`, `kw_auth_bypass`, `kw_path_traversal`, `kw_deserialization`, `kw_privilege_escalation`, `kw_sql_injection`, `kw_exploited`) |
| Similarity (Granite) | `kev_sim_max`, `kev_sim_top5`: cosine similarity of the description's Granite embedding (`ibm-granite/granite-embedding-small-english-r2`) to KEV entries added by the snapshot, excluding itself |
| Exposure | `days_to_cutoff` |

## Columns not used, and why

| Column | Why not |
| --- | --- |
| `nvd_status`, `n_affected_cpes`, `n_references`, anything from `references.csv` | Today's values, not as of the snapshot. NIST analyses exploited vulnerabilities first, so these encode the answer (see the leakage audit). |
| `cvss3_source`, NIST-supplied CVSS 3 | NIST's score appears after its analysis, which favours exploited vulnerabilities. CNA-supplied CVSS is kept. |
| `last_modified` | Changes after exploitation. |
| raw `epss` | EPSS changed models in March 2025, so raw scores shift between years. The monthly percentile doesn't. |
| `assigner` (raw string) | Would let the model memorise assigners; its history columns carry the signal. |
| `cve_id`, `fold`, `published`, `snapshot_month`, `snapshot_end`, `cutoff` | Identifiers and timing. |

## Backtest results (SHE-8 model, submission v1; see SHE-111 below for v2)

Hits at K and at 500. LightGBM rows are the mean [min-max] over 5 seeds, and the
rank-averaged ensemble of the 5.

| Ranking | 2025 hits@243 | 2025 hits@500 | 2024 hits@198 (time-reversed for models) | 2024 hits@500 |
| --- | --- | --- | --- | --- |
| CVSS first (README) | 8 | 8 | 2 | 3 |
| EPSS first (README) | 8 | 8 | 3 | 4 |
| Exploit code, then EPSS (README) | 13 | 17 | 6 | 8 |
| Safety ranker (EPSS percentile + 1.0 x exploit code) | 13 | 17 | 5 | 10 |
| LightGBM, mean [min-max] | 10.2 [9-14] | 18.0 [18-18] | 7.8 [7-8] | 11.8 [11-12] |
| LightGBM, 5-seed ensemble | 9 | 18 | 8 | 13 |

The LightGBM model beats every baseline at 500 in both directions and at K in the
time-reversed check, but **not** at K = 243 on 2025 (10.2 vs 13). With 48 positives, one
seed ranges from 9 to 14. The safety ranker's weights were chosen on 2024 only.

## Ablations (primary protocol, 5 seeds)

| Without | 2025 hits@243 | change | 2025 hits@500 | change |
| --- | --- | --- | --- | --- |
| (all features) | 10.2 [9-14] | | 18.0 | |
| signals | 6.2 [6-7] | -4.0 | 10.0 | -8.0 |
| assigner history | 11.0 [10-12] | +0.8 | 13.4 | -4.6 |
| similarity (Granite) | 11.2 [10-13] | +1.0 | 14.4 | -3.6 |
| keywords | 10.4 [10-11] | +0.2 | 15.2 | -2.8 |
| exposure | 11.2 [10-13] | +1.0 | 16.6 | -1.4 |
| severity and CWE | 10.4 [10-11] | +0.2 | 16.8 | -1.2 |
| only signals | 2.8 [2-3] | -7.4 | 8.0 | -10.0 |

Signals matter most. The other groups barely move hits@243 (within seed noise) but each
adds hits further down the list; Granite similarity is worth 3.6 hits at 500.

## Leakage audit

The same model with the banned columns added (`nvd_status`, `n_affected_cpes`,
`n_references`, whether NIST supplied the CVSS score, and that score):

| Model | 2025 hits@243 | 2025 hits@500 | 2024 hits@198 (time-reversed) |
| --- | --- | --- | --- |
| Clean | 10.2 [9-14] | 18.0 | 7.8 [7-8] |
| With leaky columns ("cheater") | 19.6 [19-21] | 23.8 | 15.6 [14-18] |
| Clean without `kw_exploited` | 9.0 [8-10] | 17.6 | 8.4 [8-9] |

Share with `nvd_status = 'Analyzed'` today: **100%** of 2024 and 2025 positives, against
42.3% and 50.1% of negatives, and 43.0% of the 2026 scoreboard. NIST analyses
exploited vulnerabilities first, so in the backtest the status almost gives the answer;
for 2026 it hasn't happened yet. The cheater's doubled score would not hold, so it is
never used: the submission writer refuses scores from a model that saw these columns.
Removing `kw_exploited` changes little in either direction, so it stays.

## Parameters of the SHE-8 model (`src/backend/modeling/params.json`)

`num_leaves` 15, `min_child_samples` 100, `learning_rate` 0.03, 600 trees,
`feature_fraction` 0.8, `bagging_fraction` 0.8, `bagging_freq` 1, `lambda_l2` 1.0,
`max_pos_weight` 1 (no class reweighting). Chosen from a 54-combination grid by the sum
of 2025 mean hits@243 and time-reversed 2024 mean hits@198 (3 seeds), ties to the
simpler model. The class-weight cap was added to the grid because reweighting positives
by up to 200x made the model overfit the 27 training positives (3.2 hits@243 on 2025).

## Submission (v2, SHE-116)

- `outputs/top500.csv`: one column, `cve_id`, 500 unique scoreboard IDs, from the
  **blend at alpha 0.25**: `0.25 x pct_rank(model) + 0.75 x pct_rank(safety)` within the
  2026 fold, ties by `cve_id`. The model part is the monotone-constrained LightGBM below
  (benchmark labels), trained on 2024 + 2025 with 5 seeds and rank-averaged. All 500 have
  public exploit code; 317 are also in the safety ranker's top 500.
- SHA-256 (LF line endings, as committed):
  `8bf5ac92760beb533f70c2095aaaaa223200d07ff951530c641716a997e0364f` (tag `submission-v2`).
- Earlier versions are in the history: v1 (SHE-58, LightGBM alone, `940a0e5c...`, tag
  `submission-v1`) and the safety ranker's top 500 (SHE-50).

## Model improvements and selection (SHE-111)

The SHE-8 LightGBM did not beat the README baselines at K, so four fixes were tried and
compared under one fixed rule.

**Rule.** A variant's primary score is its 2025 mean hits@243 plus its time-reversed 2024
mean hits@198 (5-seed means for tree models, one run for deterministic rankings). It
replaces the submission only if it **clearly wins**: a primary score at least 3 higher than
the current submission's, and not worse in either direction on its own. Every choice
inside a variant (parameters, blend weight, C) used the same primary score; nothing was
chosen on 2025 alone, and nothing looked at 2026.

**Label rule (training only).** "Long" variants train on KEV additions after the
snapshot up to Dec 31 of the training year before the test year: 2024-12-31 for train
2024 -> test 2025, 2025-12-31 for the time-reversed check and for the final model (the
KEV file ends Dec 31, 2025, before every 2026 snapshot). They drop `days_to_cutoff`.
Training positives: 2024 goes from 27 to 33 (to Dec 2024) or 46 (to Dec 2025); 2025 from
48 to 52. Evaluation always uses the benchmark label. The chosen variant uses benchmark
labels.

**Variants.**

- *Long labels* with the SHE-8 parameters.
- *Constrained LightGBM*: monotone +1 on EPSS percentile, the exploit flags, assigner KEV
  history and KEV similarity; `max_depth` 3; a 24-combination grid per label mode. Chosen:
  3 leaves, `min_child_samples` 100, learning rate 0.02 with 400 trees, all features, no
  class reweighting (`modeling/params_constrained.json`).
- *Blend* of the best model with the safety ranker, alpha in {0, 0.25, 0.5, 0.75, 1}.
- *Logistic regression* on the core features (signals, assigner history, similarity) with
  missing flags and two exploit-code interactions, C chosen from {0.01, 0.1, 1}.

**Comparison** (`outputs/comparison.csv`; hits@K mean [min-max], hits@500 mean):

| Variant | Labels | 2025 hits@243 | 2025 hits@500 | 2024 hits@198 (reversed) | 2024 hits@500 | Primary score |
| --- | --- | --- | --- | --- | --- | --- |
| CVSS first | | 8 | 8 | 2 | 3 | 10.0 |
| EPSS first | | 8 | 8 | 3 | 4 | 11.0 |
| Exploit code, then EPSS | | 13 | 17 | 6 | 8 | 19.0 |
| Safety ranker (= blend alpha 0) | | 13 | 17 | 5 | 10 | 18.0 |
| SHE-8 LightGBM (v1 submission) | benchmark | 10.2 [9-14] | 18.0 | 7.8 [7-8] | 11.8 | 18.0 |
| SHE-8 LightGBM | long | 9.4 [8-12] | 15.6 | 7.4 [6-9] | 10.6 | 16.8 |
| Constrained LightGBM (= blend alpha 1) | benchmark | 12.8 [11-14] | 15.2 | 8.0 [8-8] | 12.2 | 20.8 |
| Constrained LightGBM | long | 12.0 [10-13] | 15.0 | 8.0 [8-8] | 10.4 | 20.0 |
| **Blend alpha 0.25** | benchmark | **15.4 [15-16]** | 18.0 | **8.6 [8-9]** | 9.0 | **24.0** |
| Blend alpha 0.5 | benchmark | 14.4 [13-15] | 16.2 | 8.8 [8-9] | 9.0 | 23.2 |
| Blend alpha 0.75 | benchmark | 12.2 [12-13] | 15.8 | 8.0 [8-8] | 10.0 | 20.2 |
| Logistic regression (C 0.01) | benchmark | 15 | 21 | 5 | 6 | 20.0 |
| Logistic regression (C 0.01) | long | 13 | 19 | 4 | 6 | 17.0 |

**Decision** (`outputs/selection.json`): blend alpha 0.25 clearly wins: primary score
24.0 against 18.0 (+6.0), better on 2025 (15.4 vs 10.2) and on the time-reversed 2024
check (8.6 vs 7.8). Blend alpha 0.5 also qualifies (+5.2); the rule takes the higher
score. Longer training labels didn't help any model here. Caveat: the blend trades some
hits deeper in the list for hits near the top: its 2024 hits@500 (9.0) is lower than the
v1 model's (11.8), while the rule scores hits at K, the benchmark's own pick rate.

## Lean feature sets (after SHE-117)

The univariate report (`modeling/feature_report.py`, SHE-117) was used to prune features
with a rule fixed before any backtest: AUC (best direction) at least 0.55 in every
selection year with the same direction, at least 5 positives with a value (drops
`cvss4_score`, which has 1 and 6), one feature per pair with |Spearman rho| >= 0.85, and
monotone constraints in each kept numeric feature's direction. Same constrained
parameters as above, benchmark labels, 5 seeds.

| Variant | 2025 hits@243 | 2025 hits@500 | 2024 hits@198 (reversed) | 2024 hits@500 | Primary score |
| --- | --- | --- | --- | --- | --- |
| Lean, selected on both years (16 features) | 13.0 [13-13] | 15.0 | 10.0 [10-10] | 13.8 | 23.0 |
| Lean, selected on the training year only | 13.0 [13-13] | 14.6 | 8.2 [8-9] | 12.8 | 21.2 |
| Blend alpha 0.25 with lean (both years) | 15.4 [15-16] | 17.4 | 9.0 [9-9] | 9.0 | 24.4 |
| Blend alpha 0.25 with lean (training year only) | 15.4 [15-16] | 18.0 | 9.0 [9-9] | 9.0 | 24.4 |
| Current submission (blend alpha 0.25, full constrained model) | 15.4 [15-16] | 18.0 | 8.6 [8-9] | 9.0 | 24.0 |

Pruning helps the model on its own (23.0 vs 20.8 for the full constrained model), but
once blended with the safety ranker the gain is +0.4, far below the +3 needed to replace
the submission, so `top500.csv` is unchanged. The "both years" selection saw the test
year's labels, so its backtest is optimistic; the training-year-only ("nested") version
is the honest one and reaches the same blended score.

## Known limits

- **Few positives.** 27 and 48 positives per fold: single-seed results swing by about
  plus or minus 3 hits. All comparisons use 5-seed means.
- **KEV descriptions are today's versions.** The similarity reference set uses current
  KEV descriptions, which may have been edited after exploitation.
- **KEV runs to Dec 2025.** Labels end on Nov 4 of each fold year, so this is enough
  for the backtest, but the model has seen no 2026 exploitation.
- **Point in time.** Features use only what was known at the end of the snapshot month,
  except the description text (today's version, see `kw_exploited` in the audit).

## How to reproduce

From `backend/`, with the 8 CSVs in `data/raw/`:

```
uv sync
uv run python -m backend.pipeline.load
uv run python -m backend.pipeline.clean
uv run python -m backend.pipeline.population
uv run python -m backend.pipeline.embeddings --export     # then scripts/colab_embed.py on a Colab T4
uv run python -m backend.pipeline.embeddings --import path/to/embeddings.parquet
#   (or, locally on CPU, a few hours: uv run python -m backend.pipeline.embeddings)
uv run python -m backend.pipeline.similarity
uv run python -m backend.pipeline.features
uv run python -m backend.modeling.baselines
uv run python -m backend.modeling.safety
uv run python -m backend.modeling.train
uv run python -m backend.modeling.tune                    # optional: params.json is committed
uv run python -m backend.modeling.ablations
uv run python -m backend.pipeline.features --audit
uv run python -m backend.modeling.audit
uv run python -m backend.modeling.final                   # v1 (SHE-58): LightGBM alone
uv run python -m backend.modeling.comparison              # SHE-111 comparison table
uv run python -m backend.modeling.constrained
uv run python -m backend.modeling.blend
uv run python -m backend.modeling.logreg
uv run python -m backend.modeling.select                  # v2: writes top500.csv and predictions.parquet
```

`select` retrains the winner and rebuilds `predictions.parquet` itself;
`uv run python -m backend.modeling.serving` rebuilds it from the saved final models.
