"""
Decision engine for Stage 3 – classifies deletion requests based on evidence.

The engine respects the challenge contract:
1. Resolve user identities via `resolve_user_ids` (current + historic identifiers).
2. Apply the `audit_at` cutoff – only evidence captured at or before this timestamp is considered.
3. For each deletion rule that requires `DELETE`, we must find *actual* evidence proving the record was deleted. Evidence files are read as UTF‑8 text and must contain the marker `DELETE_CONFIRMED`.
4. If any required DELETE rule lacks such proof, the request is `INCOMPLETE`.
5. If no user can be resolved, the request is `NOT_APPLICABLE`.
6. Reported workflow statuses are ignored – they are treated as untrusted claims.

The public API is `classify_requests` which returns a mapping
`{case_id: status}` where status is one of "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE".
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Dict

from .resolve import resolve_user_ids, filter_evidence

EVIDENCE_MARKER = "DELETE_CONFIRMED"


def _evidence_proves_deletion(evidence_path: str) -> bool:
    """Return True if the evidence file at *evidence_path* contains the deletion marker.

    The function assumes the path is relative to the repository root. If the file cannot be
    opened or does not contain the marker, it returns False.
    """
    try:
        with open(evidence_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if EVIDENCE_MARKER in line:
                    return True
    except Exception:
        # Any I/O problem means we cannot prove deletion.
        return False


def _rule_has_proof(rule: Dict[str, str], evidences: List[Dict[str, str]]) -> bool:
    """Determine whether any evidence in *evidences* satisfies the DELETE requirement for *rule*.

    The contract requires the evidence to be linked to the data category. We perform a simple
    heuristic: the evidence file path must contain the rule's `data_category` (case‑insensitive)
    **and** the file must contain the `DELETE_CONFIRMED` marker.
    """
    category = rule.get("data_category", "").strip().lower()
    if not category:
        return False
    for ev in evidences:
        file_path = ev.get("file_path", "").lower()
        if category in file_path:
            # Resolve the actual file on disk (relative to repo root)
            full_path = Path(ev.get("file_path", "")).resolve()
            if _evidence_proves_deletion(full_path):
                return True
    return False


def classify_requests(
    requests: List[Dict[str, str]],
    identities: List[Dict[str, str]],
    audit_log: List[Dict[str, str]],
    system_activity: List[Dict[str, str]],
    deletion_rules: List[Dict[str, str]],
    evidence_files: List[Dict[str, str]],
) -> Dict[str, str]:
    """Classify each request according to the contract.

    Parameters
    ----------
    requests: List of rows from `deletion_requests.csv`.
    identities: Rows from `user_identities.csv`.
    audit_log: Rows from `user_audit_log.csv`.
    system_activity: Rows from `system_activity.csv` (unused in the minimal implementation).
    deletion_rules: Rows from `deletion_rules.csv`.
    evidence_files: Rows from `evidence_files.csv`.

    Returns
    -------
    Dict mapping ``case_id`` to one of "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE".
    """
    result: Dict[str, str] = {}

    for req in requests:
        case_id = req.get("case_id")
        email = req.get("email", "").strip()
        audit_at = req.get("audit_at")
        if not case_id or not email or not audit_at:
            result[case_id or ""] = "NOT_APPLICABLE"
            continue

        # 1. Resolve user identifiers (could be multiple user_ids).
        user_ids = resolve_user_ids(email, identities, audit_log)
        if not user_ids:
            result[case_id] = "NOT_APPLICABLE"
            continue

        # 2. Apply cutoff to evidence files.
        evid_at_cutoff = filter_evidence(evidence_files, audit_at)

        # 3. Evaluate each deletion rule that requires an actual DELETE.
        missing_proof = False
        for rule in deletion_rules:
            required_action = rule.get("required_action", "").strip().upper()
            if required_action != "DELETE":
                continue  # Non‑delete actions are considered satisfied.
            if not _rule_has_proof(rule, evid_at_cutoff):
                missing_proof = True
                break

        result[case_id] = "INCOMPLETE" if missing_proof else "COMPLETE"

    return result
