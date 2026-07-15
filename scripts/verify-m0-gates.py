#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fail-closed validation for the authoritative M0 gate register."""

from __future__ import annotations

import copy
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs/m0/gate-register.json"
UI_DOCUMENTS = (
    ROOT / "docs/m0/ui-feasibility.md",
    ROOT / "docs/m0/dioxus-ui-feasibility.md",
)
XTASK_SOURCE = ROOT / "xtask/src/main.rs"
REQUIRED_GATE_KEYS = {
    "id", "title", "phase", "owner", "status", "evidence_tier",
    "required_tier", "source_document", "dependencies", "evidence",
    "non_claim",
}
REQUIRED_EVIDENCE_KEYS = {
    "kind", "commit", "artifact", "reviewer", "attestation",
    "reviewed_at", "expires_at",
}
REQUIRED_REGISTER_KEYS = {
    "schema_version",
    "status_order",
    "evidence_tier_order",
    "ui_baseline_approved",
    "review_policy",
    "gates",
}
REQUIRED_REVIEW_POLICY_KEYS = {
    "qualifying_independent_reviewer",
    "physical_or_distribution_pass_requires",
}
CANONICAL_STATUSES = ["open", "diagnostic", "blocked", "failed", "passed"]
CANONICAL_TIERS = [
    "none",
    "source",
    "host",
    "simulator",
    "device-unsigned",
    "device-signed",
    "distribution-signed",
]
GATE_ID = re.compile(r"^(?:M0|M1)-[A-Z]+-\d{3}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def error(errors: list[str], message: str) -> None:
    errors.append(message)


def parse_date(value: Any, label: str, errors: list[str]) -> dt.datetime | None:
    if not isinstance(value, str):
        error(errors, f"{label} must be an ISO 8601 timestamp")
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        error(errors, f"{label} is not an ISO 8601 timestamp")
        return None
    if parsed.tzinfo is None:
        error(errors, f"{label} must include a timezone")
        return None
    return parsed


def validate_artifact(value: Any, gate_id: str, errors: list[str]) -> None:
    if not isinstance(value, dict) or set(value) != {"locator", "sha256", "redacted"}:
        error(errors, f"{gate_id}: artifact must contain locator, sha256, and redacted")
        return
    if not isinstance(value["locator"], str) or not value["locator"].strip():
        error(errors, f"{gate_id}: artifact.locator must be a non-empty string")
    if not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"]):
        error(errors, f"{gate_id}: artifact.sha256 must be a lowercase SHA-256 digest")
    if value["redacted"] is not True:
        error(errors, f"{gate_id}: signed evidence artifact must be explicitly redacted")


def validate_attestation(value: Any, reviewer: Any, gate_id: str, errors: list[str]) -> None:
    required = {"implementer", "reviewer", "competence", "statement"}
    if not isinstance(value, dict) or set(value) != required:
        error(errors, f"{gate_id}: attestation must identify implementer, reviewer, competence, and statement")
        return
    for key in required:
        if not isinstance(value[key], str) or not value[key].strip():
            error(errors, f"{gate_id}: attestation.{key} must be a non-empty string")
    if value.get("reviewer") != reviewer:
        error(errors, f"{gate_id}: attestation reviewer must match evidence.reviewer")
    if value.get("implementer") == value.get("reviewer"):
        error(errors, f"{gate_id}: implementer cannot independently review their own evidence")


def table_statuses(path: Path, errors: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        matches = re.findall(r"`(M0-(?:SLINT|DIOXUS)-\d{3}|open|diagnostic|blocked|failed|passed)`", line)
        if not matches:
            continue
        gate_ids = [item for item in matches if item.startswith("M0-")]
        statuses = [item for item in matches if not item.startswith("M0-")]
        if len(gate_ids) != 1 or len(statuses) != 1:
            error(errors, f"{path.relative_to(ROOT)}:{number}: malformed registered UI table row")
            continue
        gate_id, status = gate_ids[0], statuses[0]
        if gate_id in result:
            error(errors, f"{path.relative_to(ROOT)}:{number}: duplicate table ID {gate_id}")
        result[gate_id] = status
    return result


def validate_xtask_isolation(errors: list[str]) -> None:
    """Ensure the documented diagnostic-only enforcement hook remains present."""
    try:
        source = XTASK_SOURCE.read_text(encoding="utf-8")
    except OSError as exc:
        error(errors, f"cannot read xtask dependency-isolation source: {exc}")
        return
    for marker in ("check_slint_dependency", "check_dioxus_dependency", "tersa-slint-spike", "tersa-dioxus-spike"):
        if marker not in source:
            error(errors, f"xtask dependency isolation is missing marker {marker}")


def validate(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["register root must be an object"]
    if set(data) != REQUIRED_REGISTER_KEYS:
        error(errors, "register must contain exactly the required top-level fields")
    if data.get("schema_version") != 1:
        error(errors, "schema_version must be 1")
    statuses = data.get("status_order")
    tiers = data.get("evidence_tier_order")
    if statuses != CANONICAL_STATUSES:
        error(errors, "status_order must be the strict canonical ordering")
    if tiers != CANONICAL_TIERS:
        error(errors, "evidence_tier_order must be the strict canonical ordering")
    if data.get("ui_baseline_approved") is not False:
        error(errors, "ui_baseline_approved must be false until a production baseline is accepted")
    review_policy = data.get("review_policy")
    if not isinstance(review_policy, dict) or set(review_policy) != REQUIRED_REVIEW_POLICY_KEYS:
        error(errors, "review_policy must contain exactly the required fields")
    else:
        if not isinstance(review_policy["qualifying_independent_reviewer"], str) or not review_policy["qualifying_independent_reviewer"].strip():
            error(errors, "review_policy.qualifying_independent_reviewer must be non-empty")
        required_pass_fields = review_policy["physical_or_distribution_pass_requires"]
        if required_pass_fields != ["commit", "artifact", "reviewer", "attestation", "reviewed_at", "expires_at"]:
            error(errors, "review_policy physical pass fields must use the canonical ordering")
    gates = data.get("gates")
    if not isinstance(gates, list) or not gates:
        return errors + ["gates must be a non-empty array"]
    ids: set[str] = set()
    gate_by_id: dict[str, dict[str, Any]] = {}
    tier_order = {tier: index for index, tier in enumerate(CANONICAL_TIERS)}
    for index, gate in enumerate(gates):
        label = f"gates[{index}]"
        if not isinstance(gate, dict) or set(gate) != REQUIRED_GATE_KEYS:
            error(errors, f"{label} must contain exactly the required gate fields")
            continue
        gate_id = gate["id"]
        if not isinstance(gate_id, str) or not GATE_ID.fullmatch(gate_id):
            error(errors, f"{label}.id is not a stable gate ID")
            continue
        if gate_id in ids:
            error(errors, f"duplicate gate ID {gate_id}")
        ids.add(gate_id)
        gate_by_id[gate_id] = gate
        for key in ("title", "phase", "owner", "source_document", "non_claim"):
            if not isinstance(gate[key], str) or not gate[key].strip():
                error(errors, f"{gate_id}.{key} must be a non-empty string")
        if gate["status"] not in CANONICAL_STATUSES:
            error(errors, f"{gate_id}.status is unknown")
        if gate["evidence_tier"] not in tier_order or gate["required_tier"] not in tier_order:
            error(errors, f"{gate_id} has an unknown evidence tier")
        if isinstance(gate["source_document"], str) and not (ROOT / gate["source_document"]).is_file():
            error(errors, f"{gate_id}.source_document does not exist")
        if gate["phase"] not in {"M0", "M1"} or not gate_id.startswith(f"{gate['phase']}-"):
            error(errors, f"{gate_id}.phase must match the gate ID")
        if not isinstance(gate["dependencies"], list) or not all(isinstance(item, str) for item in gate["dependencies"]):
            error(errors, f"{gate_id}.dependencies must be an array of IDs")
        evidence = gate["evidence"]
        if not isinstance(evidence, dict) or set(evidence) != REQUIRED_EVIDENCE_KEYS:
            error(errors, f"{gate_id}.evidence must contain exactly the required fields")
            continue
        if not isinstance(evidence["kind"], str) or not evidence["kind"]:
            error(errors, f"{gate_id}.evidence.kind must be a non-empty string")
        if evidence["kind"] == "none" and any(evidence[key] is not None for key in REQUIRED_EVIDENCE_KEYS - {"kind"}):
            error(errors, f"{gate_id}: none evidence cannot contain historical claims")
        review_fields = ("reviewer", "attestation", "reviewed_at", "expires_at")
        review_values = [evidence[key] for key in review_fields]
        if any(value is not None for value in review_values) and not all(review_values):
            error(errors, f"{gate_id}: review identity, attestation, and expiry metadata are all required together")
        if gate["status"] == "passed":
            if tier_order.get(gate["evidence_tier"], -1) < tier_order.get(gate["required_tier"], 99):
                error(errors, f"{gate_id}: passed status does not meet required evidence tier")
            if gate["phase"] == "M1" or gate_id.startswith("M1-"):
                error(errors, f"{gate_id}: M1 cannot pass while ui_baseline_approved is false")
            if gate_id.startswith(("M0-SLINT-", "M0-DIOXUS-")):
                error(errors, f"{gate_id}: production UI cannot pass while ui_baseline_approved is false")
        if gate["required_tier"] in {"device-signed", "distribution-signed"} and gate["status"] == "passed":
            for key in ("commit", "artifact", "reviewer", "attestation", "reviewed_at", "expires_at"):
                if not evidence[key]:
                    error(errors, f"{gate_id}: signed pass requires evidence.{key}")
            if not isinstance(evidence["commit"], str) or not COMMIT.fullmatch(evidence["commit"]):
                error(errors, f"{gate_id}: signed pass requires an exact 40-character commit SHA")
            validate_artifact(evidence["artifact"], gate_id, errors)
            if not isinstance(evidence["reviewer"], str) or not evidence["reviewer"].strip():
                error(errors, f"{gate_id}: signed pass requires a named reviewer")
            validate_attestation(evidence["attestation"], evidence["reviewer"], gate_id, errors)
            reviewed = parse_date(evidence["reviewed_at"], f"{gate_id}.evidence.reviewed_at", errors)
            expiry = parse_date(evidence["expires_at"], f"{gate_id}.evidence.expires_at", errors)
            if reviewed and expiry and expiry <= reviewed:
                error(errors, f"{gate_id}: evidence expiry must follow review")
            if reviewed and reviewed > dt.datetime.now(tz=dt.UTC):
                error(errors, f"{gate_id}: evidence review cannot be dated in the future")
            if expiry and expiry <= dt.datetime.now(tz=dt.UTC):
                error(errors, f"{gate_id}: evidence review has expired")
        elif all(review_values):
            validate_attestation(evidence["attestation"], evidence["reviewer"], gate_id, errors)
            reviewed = parse_date(evidence["reviewed_at"], f"{gate_id}.evidence.reviewed_at", errors)
            expiry = parse_date(evidence["expires_at"], f"{gate_id}.evidence.expires_at", errors)
            if reviewed and expiry and expiry <= reviewed:
                error(errors, f"{gate_id}: evidence expiry must follow review")
    for gate in gate_by_id.values():
        for dependency in gate["dependencies"]:
            if dependency not in ids:
                error(errors, f"{gate['id']}: unknown dependency {dependency}")
    table_ids: dict[str, str] = {}
    for document in UI_DOCUMENTS:
        table_ids.update(table_statuses(document, errors))
    registered_ui_ids = {gate_id for gate_id in ids if gate_id.startswith(("M0-SLINT-", "M0-DIOXUS-"))}
    if set(table_ids) != registered_ui_ids:
        error(errors, "UI Markdown table IDs must exactly match registered UI gate IDs")
    for gate_id, table_status in table_ids.items():
        if gate_by_id.get(gate_id, {}).get("status") != table_status:
            error(errors, f"{gate_id}: Markdown status does not match register")
    validate_xtask_isolation(errors)
    return errors


def load_register() -> Any:
    try:
        return json.loads(REGISTER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"M0 gate validation failed: cannot read register: {exc}") from exc


def self_test(data: Any) -> list[str]:
    failures: list[str] = []
    now = dt.datetime.now(tz=dt.UTC)
    reviewed_at = (now - dt.timedelta(days=1)).isoformat()
    expires_at = (now + dt.timedelta(days=30)).isoformat()
    mutated = copy.deepcopy(data)
    mutated["gates"][0]["status"] = "PASS locally"
    errors = validate(mutated)
    if not any("status is unknown" in message for message in errors):
        failures.append("negative status mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    mutated["gates"] = mutated["gates"][1:]
    errors = validate(mutated)
    if not any("UI Markdown table IDs must exactly match" in message for message in errors):
        failures.append("negative missing UI ID mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    signed_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-012")
    signed_gate["status"] = "passed"
    signed_gate["evidence_tier"] = "distribution-signed"
    signed_gate["evidence"]["kind"] = "distribution"
    errors = validate(mutated)
    if not any("signed pass requires evidence.commit" in message for message in errors):
        failures.append("negative unsigned distribution-pass mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    ui_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-011")
    ui_gate["status"] = "passed"
    ui_gate["evidence_tier"] = "device-signed"
    ui_gate["evidence"].update(
        {
            "kind": "device-run",
            "commit": "a" * 40,
            "artifact": {"locator": "evidence.json", "sha256": "b" * 64, "redacted": True},
            "reviewer": "reviewer",
            "attestation": {
                "implementer": "implementer",
                "reviewer": "reviewer",
                "competence": "Apple platform review",
                "statement": "I independently reviewed the commit-bound evidence.",
            },
            "reviewed_at": reviewed_at,
            "expires_at": expires_at,
        }
    )
    errors = validate(mutated)
    if not any("production UI cannot pass" in message for message in errors):
        failures.append("negative UI pass without a baseline unexpectedly passed")
    mutated = copy.deepcopy(data)
    signed_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-012")
    signed_gate["status"] = "passed"
    signed_gate["evidence_tier"] = "distribution-signed"
    signed_gate["evidence"].update(
        {
            "kind": "distribution",
            "commit": "a" * 40,
            "artifact": {"locator": "evidence.json", "sha256": "b" * 64, "redacted": True},
            "reviewer": "same-person",
            "attestation": {
                "implementer": "same-person",
                "reviewer": "same-person",
                "competence": "Release review",
                "statement": "I reviewed my own evidence.",
            },
            "reviewed_at": reviewed_at,
            "expires_at": expires_at,
        }
    )
    errors = validate(mutated)
    if not any("implementer cannot independently review" in message for message in errors):
        failures.append("negative self-review mutation unexpectedly passed")
    return failures


def main() -> int:
    data = load_register()
    errors = validate(data)
    if "--self-test" in sys.argv:
        errors.extend(self_test(data))
    if errors:
        print("M0 gate validation failed:", file=sys.stderr)
        print("\n".join(f"- {message}" for message in errors), file=sys.stderr)
        return 1
    print("M0 gate register validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
