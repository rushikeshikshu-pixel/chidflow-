from __future__ import annotations

import pytest
from benchmarks.swe_agent_benchmark import SWEAgentSecurityBenchmark


def test_swe_agent_security_benchmark_evaluation():
    res = SWEAgentSecurityBenchmark.evaluate_all()
    assert res["total_tasks"] == 5
    assert "5/5" in res["chidflow_success_rate"]
    assert "0%" in res["false_positive_rate"]
    assert len(res["details"]) == 5
    for task in res["details"]:
        assert task["chidflow_success"] is True
