"""Unit tests for the SHE-54 audit-only step and its guards."""

import duckdb
import pytest

from backend.modeling import audit
from backend.modeling import features as mf
from backend.pipeline.features import AUDIT_COLUMNS, add_audit_columns_sql, check_columns


@pytest.fixture
def con():
    con = duckdb.connect()
    con.execute("CREATE TABLE f AS SELECT 'CVE-1' AS cve_id, 2024 AS fold, 0.5 AS epss_pct")
    con.execute(
        """
        CREATE TABLE v AS SELECT
            'CVE-1' AS cve_id, 'Analyzed' AS nvd_status, 3 AS n_affected_cpes,
            7 AS n_references, 'nvd@nist.gov' AS cvss3_source, 9.8::DOUBLE AS cvss3_score,
            'something else' AS description
        """
    )
    return con


def test_audit_step_adds_only_the_listed_columns(con):
    before = [r[0] for r in con.execute("DESCRIBE f").fetchall()]
    after = [r[0] for r in con.execute(f"DESCRIBE {add_audit_columns_sql('f', 'v')}").fetchall()]
    assert after == before + AUDIT_COLUMNS
    row = con.execute(f"SELECT * FROM ({add_audit_columns_sql('f', 'v')})").fetchone()
    assert row[-5:] == ("Analyzed", 3, 7, 1, pytest.approx(9.8))


def test_normal_build_still_refuses_the_banned_columns():
    with pytest.raises(ValueError, match="Banned"):
        check_columns([*mf.FEATURES, *AUDIT_COLUMNS])
    assert set(check_columns(AUDIT_COLUMNS, audit=True)) == {
        "nvd_status", "n_affected_cpes", "n_references",
    }  # fmt: skip


def test_audit_models():
    assert audit.MODELS["clean"] == mf.FEATURES
    assert audit.MODELS["cheater"] == mf.FEATURES + AUDIT_COLUMNS
    assert set(mf.FEATURES) - set(audit.MODELS["clean_without_kw_exploited"]) == {"kw_exploited"}
    assert not set(AUDIT_COLUMNS) & set(mf.FEATURES)
