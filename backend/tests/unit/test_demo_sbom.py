import json

from backend.core.config import DEMO_DIR


def test_demo_sbom_shape():
    bom = json.loads((DEMO_DIR / "acme_sbom.cdx.json").read_text(encoding="utf-8"))
    assert bom["bomFormat"] == "CycloneDX"
    assert len(bom["components"]) == 22
    assert all(c.get("cpe") or c.get("purl") for c in bom["components"])
