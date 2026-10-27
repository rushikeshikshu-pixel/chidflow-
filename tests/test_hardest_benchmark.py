from __future__ import annotations

import pytest
from benchmarks.hardest_frontier_benchmark import HardestFrontierBenchmark


def test_hardest_frontier_benchmark_full_defense():
    res = HardestFrontierBenchmark.evaluate_all()
    assert res["total_scenarios"] == 8
    assert "8/8" in res["chidflow_score"]
    assert len(res["details"]) == 8
    for d in res["details"]:
        assert d["passed"] is True
