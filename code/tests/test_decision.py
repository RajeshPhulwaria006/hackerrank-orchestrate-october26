# Tests for the decision engine (Stage 3).

import pytest
from pathlib import Path
from code.decision import classify_requests


def _create_evidence(tmp_path: Path, filename: str, content: str, captured_at: str) -> dict:
    """Create a temporary evidence file and return its metadata dict."""
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    return {
        "file_id": f"evidence_{filename}",
        "file_path": str(file_path),
        "origin": "test",
        "captured_at": captured_at,
    }


@pytest.fixture
def base_data(tmp_path):
    # Minimal deletion rule requiring DELETE for category 'records'
    deletion_rules = [{"required_action": "DELETE", "data_category": "records"}]
    identities = [{
        "user_id": "u123",
        "email": "user@example.com",
        "name": "User",
        "phone": "123",
        "email_hash": "hash",
        "snapshot_update_time": "2026-01-01T00:00:00Z",
    }]
    audit_log = []
    system_activity = []
    return identities, audit_log, system_activity, deletion_rules, tmp_path


def test_complete_case(base_data):
    identities, audit_log, system_activity, deletion_rules, tmp_path = base_data
    ev = _create_evidence(
        tmp_path,
        "evidence.txt",
        "some info\nDELETE_CONFIRMED\n",
        "2026-09-01T00:00:00Z",
    )
    evidence_files = [ev]
    requests = [{"case_id": "c1", "email": "user@example.com", "audit_at": "2026-10-01T00:00:00Z"}]
    result = classify_requests(requests, identities, audit_log, system_activity, deletion_rules, evidence_files)
    assert result["c1"] == "COMPLETE"

def test_incomplete_missing_marker(base_data):
    identities, audit_log, system_activity, deletion_rules, tmp_path = base_data
    ev = _create_evidence(
        tmp_path,
        "evidence.txt",
        "some info without marker",
        "2026-09-01T00:00:00Z",
    )
    evidence_files = [ev]
    requests = [{"case_id": "c2", "email": "user@example.com", "audit_at": "2026-10-01T00:00:00Z"}]
    result = classify_requests(requests, identities, audit_log, system_activity, deletion_rules, evidence_files)
    assert result["c2"] == "INCOMPLETE"

def test_not_applicable_no_user(base_data):
    identities, audit_log, system_activity, deletion_rules, tmp_path = base_data
    ev = _create_evidence(
        tmp_path,
        "evidence.txt",
        "DELETE_CONFIRMED",
        "2026-09-01T00:00:00Z",
    )
    evidence_files = [ev]
    requests = [{"case_id": "c3", "email": "unknown@example.com", "audit_at": "2026-10-01T00:00:00Z"}]
    result = classify_requests(requests, identities, audit_log, system_activity, deletion_rules, evidence_files)
    assert result["c3"] == "NOT_APPLICABLE"

def test_cutoff_ignores_late_evidence(base_data):
    identities, audit_log, system_activity, deletion_rules, tmp_path = base_data
    ev = _create_evidence(
        tmp_path,
        "evidence.txt",
        "DELETE_CONFIRMED",
        "2026-11-01T00:00:00Z",
    )
    evidence_files = [ev]
    requests = [{"case_id": "c4", "email": "user@example.com", "audit_at": "2026-10-01T00:00:00Z"}]
    result = classify_requests(requests, identities, audit_log, system_activity, deletion_rules, evidence_files)
    assert result["c4"] == "INCOMPLETE"
