# code/remediation.py
"""Remediation planning utilities for Stage 4.

Generates ordered FINDING → REMEDIATION → VERIFICATION steps for
incomplete deletion requests. The steps conform to the contract
defined in AGENTS.md / problem_statement.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Set

# Operation / state tables from the contract (enhanced mapping)
FINDING_OP_MAP = {
    "DELETE": "REPORT_REMAINING_RECORD",
    "REDACT": "REPORT_EXPOSED_PII",
    "ANONYMIZE": "REPORT_EXPOSED_PII",
    "RETAIN": "REPORT_REMAINING_RECORD",  # treat as presence check
    "LEGAL_HOLD": "REPORT_ACTIVE_DATA_FLOW",
    "BACKUP": "REPORT_RESTORE_RISK",
}
FINDING_STATE_MAP = {
    "DELETE": "PRESENT",
    "REDACT": "PRESENT",
    "ANONYMIZE": "PRESENT",
    "RETAIN": "PRESENT",
    "LEGAL_HOLD": "ACTIVE",
    "BACKUP": "ACTIVE",
}
# Remediation operation/state per action
REMEDIATION_OP_MAP = {
    "DELETE": "DELETE_RECORD",
    "REDACT": "REDACT_RECORD",
    "ANONYMIZE": "ANONYMIZE_RECORD",
    "RETAIN": None,  # no remediation needed
    "LEGAL_HOLD": "BLOCK_RESTORE",
    "BACKUP": "DISABLE_DATA_FLOW",
}
REMEDIATION_STATE_MAP = {
    "DELETE": "ABSENT",
    "REDACT": "REDACTED",
    "ANONYMIZE": "ANONYMIZED",
    "LEGAl_HOLD": "BLOCKED",
    "BACKUP": "DISABLED",
}
VERIFICATION_OP_MAP = {
    "DELETE": "VERIFY_RECORD_ABSENT",
    "REDACT": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
    "RETAIN": "VERIFY_RECORD_PRESENT",
    "LEGAL_HOLD": "VERIFY_RESTORE_BLOCKED",
    "BACKUP": "VERIFY_DATA_FLOW_DISABLED",
}
VERIFICATION_STATE_MAP = {
    "DELETE": "ABSENT",
    "REDACT": "REDACTED",
    "ANONYMIZE": "ANONYMIZED",
    "RETAIN": "PRESENT",
    "LEGAL_HOLD": "BLOCKED",
    "BACKUP": "DISABLED",
}

FINDING_OP = "REPORT_REMAINING_RECORD"
FINDING_STATE = "PRESENT"
REMEDIATION_OP = "DELETE_RECORD"
REMEDIATION_STATE = "ABSENT"
VERIFICATION_OP = "VERIFY_RECORD_ABSENT"
VERIFICATION_STATE = "ABSENT"

def _category_to_resource_id(category: str) -> str:
    """Derive a deterministic resource identifier from a data category.
    This is a simple placeholder used for demonstration purposes.
    """
    return f"{category}_resource"

def generate_steps(
    case_id: str,
    rules: List[Dict[str, str]],
    evidence_by_cat: Dict[str, Dict[str, str]],
) -> List[Dict]:
    """Generate a list of step dictionaries for an incomplete case.

    Args:
        case_id: Identifier of the request (used only for ordering).
        missing_categories: Set of data_category strings for which deletion
            evidence (DELETE_CONFIRMED) was not found.
        evidence_map: Mapping data_category → evidence_id (may be empty string)
            of the evidence file that was examined for that category.

    Returns:
        Ordered list of step dicts complying with the required schema.
    """
    steps: List[Dict] = []
    step_no = 1
    for cat in sorted(missing_categories):
        resource_id = _category_to_resource_id(cat)
        evidence_id = evidence_map.get(cat, "")
        # FINDING step
        steps.append({
            "step_no": step_no,
            "phase": "FINDING",
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": FINDING_OP,
            "state": FINDING_STATE,
            "evidence_id": evidence_id,
        })
        step_no += 1
        # REMEDIATION step (future action, no evidence)
        steps.append({
            "step_no": step_no,
            "phase": "REMEDIATION",
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": REMEDIATION_OP,
            "state": REMEDIATION_STATE,
            "evidence_id": "",
        })
        step_no += 1
        # VERIFICATION step (future check, no evidence)
        steps.append({
            "step_no": step_no,
            "phase": "VERIFICATION",
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": VERIFICATION_OP,
            "state": VERIFICATION_STATE,
            "evidence_id": "",
        })
        step_no += 1
    return steps

# Helper used by main to compute missing categories and map evidence
def plan_remediation(
    request: Dict[str, str],
    identities: List[Dict[str, str]],
    audit_log: List[Dict[str, str]],
    system_activity: List[Dict[str, str]],
    deletion_rules: List[Dict[str, str]],
    evidence_files: List[Dict[str, str]],
) -> List[Dict]:
    """High‑level wrapper that determines missing DELETE categories and calls
    ``generate_steps``. Returns an empty list for COMPLETE or NOT_APPLICABLE.
    """
    from .decision import classify_requests
    # Re‑use decision logic to obtain status for a single request
    classification = classify_requests(
        [request], identities, audit_log, system_activity, deletion_rules, evidence_files
    )
    status = classification.get(request["case_id"], "INCOMPLETE")
    if status != "INCOMPLETE":
        return []

    # Identify which DELETE rules lack proof
    audit_at = request["audit_at"]
    # Filter evidence up to cutoff
    from .resolve import filter_evidence
    evid_cut = filter_evidence(evidence_files, audit_at)
    # Build a map of category -> evidence_id where file path contains category
    evidence_map: Dict[str, str] = {}
    for ev in evid_cut:
        path = ev.get("file_path", "").lower()
        for rule in deletion_rules:
            if rule.get("required_action", "").strip().upper() != "DELETE":
                continue
            cat = rule.get("data_category", "").strip().lower()
            if cat and cat in path:
                # Read file content to check for marker
                try:
                    txt = Path(ev["file_path"]).read_text(encoding="utf-8")
                except Exception:
                    txt = ""
                if "DELETE_CONFIRMED" in txt:
                    # evidence proves deletion – do not consider missing
                    continue
                # otherwise record that we examined this file
                evidence_map.setdefault(cat, ev.get("file_id", ""))
    # Determine missing categories
    missing: Set[str] = set()
    for rule in deletion_rules:
        if rule.get("required_action", "").strip().upper() != "DELETE":
            continue
        cat = rule.get("data_category", "").strip().lower()
        if not cat:
            continue
        # If we have evidence_map entry with proven marker, skip
        # (already excluded above). So if no entry, it's missing.
        if cat not in evidence_map:
            missing.add(cat)
    return generate_steps(request["case_id"], missing, evidence_map)

