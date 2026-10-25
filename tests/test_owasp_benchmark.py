import pytest
from benchmarks.owasp_benchmark import OWASPAgentBenchmark


class TestOWASPBenchmark:
    def test_owasp_benchmark_full_coverage(self):
        results = OWASPAgentBenchmark.evaluate_all()
        assert results["total_scenarios"] == 10
        assert "0%" in results["industry_standard_score"]
        assert "100%" in results["chidflow_score"]

        for d in results["details"]:
            assert d["chidflow_mitigated"] is True
            assert d["latency_ms"] < 10.0  # sub-10ms even under test overhead
