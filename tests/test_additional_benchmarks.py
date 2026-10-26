import pytest
from benchmarks.mitre_atlas_benchmark import MITREATLASBenchmark
from benchmarks.sre_resilience_benchmark import SREResilienceBenchmark


class TestAdditionalBenchmarks:
    def test_mitre_atlas_benchmark_full_coverage(self):
        results = MITREATLASBenchmark.evaluate_all()
        assert results["total_scenarios"] == 10
        assert "0%" in results["crowdstrike_edr_score"]
        assert "100%" in results["chidflow_score"]

        for d in results["details"]:
            assert d["chidflow_mitigated"] is True
            assert d["latency_ms"] < 10.0

    def test_sre_resilience_benchmark_full_coverage(self):
        results = SREResilienceBenchmark.evaluate_all()
        assert results["total_incidents"] == 5
        assert "100%" in results["serverwatch_success_rate"]
        assert results["serverwatch_average_mttr_ms"] < 5.0

        for d in results["details"]:
            assert d["healed"] is True
            assert d["receipt_issued"] is True
            assert d["serverwatch_mttr_ms"] < 5.0
