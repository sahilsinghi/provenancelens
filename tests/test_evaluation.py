"""Re-run the labelled evaluation and hold the published numbers to account (pytest -m slow)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.slow


def test_evaluation_headlines(tmp_path):
    pytest.importorskip("skimage")
    from provlens import evaluate

    items = evaluate.generate(tmp_path, per_source=6, seed=2026)
    rep = evaluate.evaluate(items, fit_models=False)
    flagged = rep["djpeg"]["flagged_share_by_kind"]
    assert flagged["authentic"] <= 0.05 and flagged["platform"] <= 0.05
    assert flagged["double_up"] >= 0.9 and flagged["splice"] >= 0.9
    assert flagged["double_down"] <= 0.1  # the documented blind spot, not a strength
    assert rep["pixel"]["ghost"]["splice_localised_rate"] >= 0.8
    binary = rep["verdicts"]["binary"]
    assert binary["specificity"] >= 0.95 and binary["recall"] >= 0.9
    m = rep["verdicts"]["matrix"]
    assert m["platform"].get("moderate", 0) + m["platform"].get("strong", 0) == 0
    assert m["authentic"].get("moderate", 0) + m["authentic"].get("strong", 0) == 0
    assert rep["verdicts"]["ai_declared_recognised"] == "4/4"
    assert rep["verdicts"]["stripped_limited_signal"] == "4/4"
