"""SHE-58 / SHE-116: the submitted top500.csv is valid and reproducible from the fixed seeds
and the config saved with the final models."""

import json

import pandas as pd
import pytest

from backend.core.config import LOGS_DIR, OUTPUTS_DIR
from backend.db.warehouse import connect
from backend.modeling import features as mf
from backend.modeling.final import final_config, submission_scores, train_final
from backend.modeling.submission import pick_top

TOP500 = OUTPUTS_DIR / "top500.csv"
LOG = LOGS_DIR / "final_log.json"

pytestmark = pytest.mark.skipif(
    not LOG.exists(), reason="no final model: run `uv run python -m backend.modeling.select`"
)


def test_top500_is_valid():
    out = pd.read_csv(TOP500)
    assert list(out.columns) == ["cve_id"]
    assert len(out) == 500
    assert out["cve_id"].is_unique
    scoreboard = {r[0] for r in connect().execute("SELECT cve_id FROM scoreboard_2026").fetchall()}
    assert set(out["cve_id"]) <= scoreboard


def test_rerun_gives_the_same_top500():
    con = connect()
    data = mf.load(con)
    config = final_config()
    models = train_final(
        data, config["params"], features=config["features"], label_end=config["label_end"],
        con=con,
    )  # fmt: skip
    scores = submission_scores(models, data[data["fold"] == 2026].reset_index(drop=True), config)
    assert pick_top(scores)["cve_id"].tolist() == pd.read_csv(TOP500)["cve_id"].tolist()
    assert json.loads(LOG.read_text())["top10"] == pick_top(scores)["cve_id"].head(10).tolist()
