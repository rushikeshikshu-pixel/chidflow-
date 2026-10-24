import pytest
from chidflow.edge_daemon import (
    DeviceType,
    EdgeDeviceDaemon,
    EdgeTaskRequest,
)


@pytest.fixture
def edge_setup():
    daemon = EdgeDeviceDaemon(
        device_id="macbook_pro_m4_dev_01",
        device_type=DeviceType.LAPTOP_WORKSTATION,
        device_secret="super_secret_tpm_macbook_key_2026",
    )
    return daemon


class TestEdgeDeviceDaemon:
    def test_untrusted_task_targeting_local_keychain_blocked(self, edge_setup):
        daemon = edge_setup

        # Remote background agent ingests dirty web scrape and tries to access ssh keys
        bad_task = EdgeTaskRequest(
            task_id="tsk_hack_01",
            device_id=daemon.device_id,
            device_type=daemon.device_type,
            agent_id="background_scraper_agent",
            action_type="EXTRACT_SSH_KEYS",
            source_origin="public_web_ingress",
            target_asset="ssh_private_keys",
        )

        verdict = daemon.evaluate_edge_task(bad_task)
        assert not verdict.allowed
        assert verdict.status_code == 403
        assert "EDGE_INVARIANT_VIOLATION" in verdict.reason
        assert verdict.passport is None
        assert verdict.severed_path is not None
        assert "ssh_private_keys" in verdict.severed_path

    def test_untrusted_task_targeting_aws_credentials_blocked(self, edge_setup):
        daemon = edge_setup

        bad_task = EdgeTaskRequest(
            task_id="tsk_hack_02",
            device_id=daemon.device_id,
            device_type=daemon.device_type,
            agent_id="untrusted_webhook_agent",
            action_type="EXFIL_AWS_KEYS",
            source_origin="https://untrusted-external-site.io",
            target_asset="aws_credentials",
        )

        verdict = daemon.evaluate_edge_task(bad_task)
        assert not verdict.allowed
        assert verdict.status_code == 403
        assert "aws_credentials" in verdict.severed_path

    def test_benign_task_cleared_with_cryptographic_passport(self, edge_setup):
        daemon = edge_setup

        # Safe internal task: compile code or format documents
        clean_task = EdgeTaskRequest(
            task_id="tsk_clean_03",
            device_id=daemon.device_id,
            device_type=daemon.device_type,
            agent_id="code_formatter_agent",
            action_type="FORMAT_CODEBASE",
            source_origin="local_scratchpad",
            target_asset="local_scratchpad",
        )

        verdict = daemon.evaluate_edge_task(clean_task)
        assert verdict.allowed
        assert verdict.status_code == 200
        assert verdict.passport is not None
        assert verdict.passport.cleared_for_cloud_settlement

        # Verify cryptographic authenticity of the passport
        is_valid = daemon.verify_edge_passport(verdict.passport)
        assert is_valid, "Passport signature verification failed"
        assert verdict.execution_latency_ms < 10.0  # Runs in single-digit ms
