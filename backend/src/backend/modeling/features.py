"""SHE-51: the model's feature whitelist and how a frame becomes model input.

The whitelist is the only source of features: nothing is inferred from the table's
columns. Deliberately left out:
- cve_id, fold, published, snapshot_month, snapshot_end, cutoff, label: identifiers,
  timing and the answer;
- assigner: the raw string would let the model memorise assigners; its history columns
  (assigner_kev_prior, assigner_cves_prior, assigner_kev_rate) carry the signal;
- epss: EPSS changed models in March 2025, so raw scores shift between 2024 and later;
  epss_pct (the percentile within the month) doesn't.
- the banned (leaky) columns of pipeline.features.BANNED_COLUMNS.
"""

import pandas as pd

from backend.pipeline.features import check_columns, features_parquet

CVSS3_METRICS = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "scope",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]
KEYWORDS = [
    "kw_unauthenticated",
    "kw_remote_code_execution",
    "kw_command_injection",
    "kw_pre_auth",
    "kw_default_config",
    "kw_auth_bypass",
    "kw_path_traversal",
    "kw_deserialization",
    "kw_privilege_escalation",
    "kw_sql_injection",
    "kw_exploited",
]
FEATURE_GROUPS: dict[str, list[str]] = {
    "signals": [
        "epss_pct",
        "exploitdb",
        "metasploit",
        "nuclei",
        "poc_github",
        "any_exploit_code",
    ],
    "assigner_history": ["assigner_kev_prior", "assigner_cves_prior", "assigner_kev_rate"],
    "severity_cwe": ["cvss3_score", *CVSS3_METRICS, "cvss4_score", "cwe_primary", "n_cwes"],
    "keywords": KEYWORDS,
    "similarity": ["kev_sim_max", "kev_sim_top5"],
    "exposure": ["days_to_cutoff"],
}
FEATURES: list[str] = [c for group in FEATURE_GROUPS.values() for c in group]
CATEGORICAL: list[str] = [*CVSS3_METRICS, "cwe_primary"]
# Categorical only in the leakage audit (SHE-54); never in FEATURES.
AUDIT_CATEGORICAL: list[str] = ["nvd_status"]
OTHER = "other"
MIN_CWE_COUNT = 30  # rarer CWEs in training become "other"

check_columns(FEATURES)  # raises if a banned column ever enters the whitelist


def load(con, folds=(2024, 2025, 2026), source: str | None = None) -> pd.DataFrame:
    """Every column of the feature table for the given folds, sorted by fold and cve_id."""
    fold_list = ", ".join(str(f) for f in folds)
    return con.execute(
        f"SELECT * FROM {source or features_parquet('features')} "
        f"WHERE fold IN ({fold_list}) ORDER BY fold, cve_id"
    ).df()


def fit_categories(df: pd.DataFrame, columns: list[str] = CATEGORICAL) -> dict[str, list[str]]:
    """Categories per column from training data; rare CWEs fold into "other"."""
    categories = {}
    for column in columns:
        counts = df[column].dropna().astype(str).value_counts()
        if column == "cwe_primary":
            counts = counts[counts >= MIN_CWE_COUNT]
        categories[column] = sorted(set(counts.index) | {OTHER})
    return categories


def prepare(
    df: pd.DataFrame,
    categories: dict[str, list[str]] | None = None,
    features: list[str] = FEATURES,
    categorical: list[str] | None = None,
) -> tuple[pd.DataFrame, dict[str, list[str]]]:
    """Model input X (whitelisted columns only) and the categories used. Pass the training
    categories when scoring: unseen or rare values become "other"; NULL stays missing."""
    categorical = categorical or [*CATEGORICAL, *AUDIT_CATEGORICAL]
    categorical = [c for c in categorical if c in features]
    if categories is None:
        categories = fit_categories(df, categorical)
    X = pd.DataFrame(index=df.index)
    for column in features:
        if column in categorical:
            values = df[column].astype("string")
            known = values.isin(categories[column]) | values.isna()
            values = values.where(known, OTHER)
            X[column] = pd.Categorical(values, categories=categories[column])
        else:
            X[column] = pd.to_numeric(df[column], errors="coerce").astype("float64")
    return X, categories
