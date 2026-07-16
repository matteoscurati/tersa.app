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
import tempfile
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
REQUIRED_ARTIFACT_KEYS = {
    "locator",
    "sha256",
    "redacted",
    "generated_at",
    "retained_until",
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
CANONICAL_REQUIRED_TIERS = {
    "M0-SLINT-001": "device-signed",
    "M0-SLINT-002": "device-signed",
    "M0-SLINT-003": "simulator",
    "M0-SLINT-004": "host",
    "M0-SLINT-005": "device-signed",
    "M0-SLINT-006": "device-signed",
    "M0-SLINT-007": "device-signed",
    "M0-SLINT-008": "device-signed",
    "M0-SLINT-009": "device-signed",
    "M0-SLINT-010": "device-signed",
    "M0-SLINT-011": "device-signed",
    "M0-SLINT-012": "distribution-signed",
    "M0-DIOXUS-001": "host",
    "M0-DIOXUS-002": "device-signed",
    "M0-DIOXUS-003": "simulator",
    "M0-DIOXUS-004": "simulator",
    "M0-DIOXUS-005": "device-signed",
    "M0-DIOXUS-006": "device-signed",
    "M0-DIOXUS-007": "device-signed",
    "M0-DIOXUS-008": "host",
    "M0-DIOXUS-009": "device-signed",
    "M0-DIOXUS-010": "device-signed",
    "M0-DIOXUS-011": "device-signed",
    "M0-DIOXUS-012": "host",
    "M0-DIOXUS-013": "device-signed",
    "M0-DIOXUS-014": "device-signed",
    "M0-DIOXUS-015": "device-signed",
    "M0-DIOXUS-016": "distribution-signed",
    "M0-CACHE-001": "device-signed",
    "M0-OAUTH-001": "device-signed",
    "M0-STORAGE-001": "device-signed",
    "M0-SEARCH-001": "device-signed",
    "M0-MIME-001": "device-signed",
    "M1-UI-001": "distribution-signed",
    "P1-MACOS-001": "distribution-signed",
    "P1-MACOS-002": "distribution-signed",
    "P1-MACOS-003": "distribution-signed",
}
CANONICAL_DEPENDENCIES = {
    "M1-UI-001": ["M0-SLINT-006", "M0-DIOXUS-009", "M0-DIOXUS-010"],
    "P1-MACOS-001": [],
    "P1-MACOS-002": [],
    "P1-MACOS-003": ["P1-MACOS-001", "P1-MACOS-002"],
}
ALLOWED_REVIEW_COMPETENCIES = {
    "accessibility",
    "apple-platform",
    "release-engineering",
    "security",
}
INDEPENDENT_REVIEW_STATEMENT = (
    "I independently reviewed the commit-bound, redacted evidence and verified the claimed result."
)
GATE_ID = re.compile(r"^(?:M0|M1|P1)-[A-Z]+-\d{3}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_ARTIFACT_LOCATOR = re.compile(
    r"^repository://evidence/(?P<commit>[0-9a-f]{40})/"
    r"(?P<path>[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$"
)
GITHUB_ACTIONS_ARTIFACT_LOCATOR = re.compile(
    r"^github-actions://runs/\d+/artifacts/\d+/manifest\.json#evidence-commit=(?P<commit>[0-9a-f]{40})$"
)
GITHUB_ARTIFACT_REVIEW_WINDOW = dt.timedelta(days=90)


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
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        error(errors, f"{label} must include a timezone")
        return None
    return parsed


def validate_artifact(
    value: Any,
    evidence_commit: Any,
    gate_id: str,
    errors: list[str],
) -> tuple[str | None, dt.datetime | None, dt.datetime | None]:
    if not isinstance(value, dict) or set(value) != REQUIRED_ARTIFACT_KEYS:
        error(errors, f"{gate_id}: artifact must contain exactly the required manifest fields")
        return None, None, None
    locator = value["locator"]
    locator_match = None
    locator_kind = None
    if isinstance(locator, str):
        locator_match = REPOSITORY_ARTIFACT_LOCATOR.fullmatch(locator)
        if locator_match:
            locator_kind = "repository"
        else:
            locator_match = GITHUB_ACTIONS_ARTIFACT_LOCATOR.fullmatch(locator)
            if locator_match:
                locator_kind = "github-actions"
    if not locator_match:
        error(errors, f"{gate_id}: artifact.locator must be an immutable, commit-bound evidence locator")
    elif locator_kind == "repository" and any(
        segment in {".", ".."} for segment in locator_match["path"].split("/")
    ):
        error(errors, f"{gate_id}: repository artifact locator cannot contain dot path segments")
    elif locator_match["commit"] != evidence_commit:
        error(errors, f"{gate_id}: artifact locator commit must exactly match evidence.commit")
    if not isinstance(value["sha256"], str) or not SHA256.fullmatch(value["sha256"]):
        error(errors, f"{gate_id}: artifact.sha256 must be a lowercase SHA-256 digest")
    if value["redacted"] is not True:
        error(errors, f"{gate_id}: evidence artifact must be explicitly redacted")
    generated = parse_date(value["generated_at"], f"{gate_id}.artifact.generated_at", errors)
    if generated and generated > dt.datetime.now(tz=dt.timezone.utc):
        error(errors, f"{gate_id}: artifact generation cannot be dated in the future")
    retained = None
    if locator_kind == "github-actions":
        retained = parse_date(
            value["retained_until"],
            f"{gate_id}.artifact.retained_until",
            errors,
        )
        if generated and retained and retained <= generated:
            error(errors, f"{gate_id}: artifact retention must follow manifest generation")
        if generated and retained and retained - generated > GITHUB_ARTIFACT_REVIEW_WINDOW:
            error(errors, f"{gate_id}: GitHub Actions artifact retention cannot exceed 90 days")
        if retained and retained <= dt.datetime.now(tz=dt.timezone.utc):
            error(errors, f"{gate_id}: GitHub Actions evidence artifact has expired")
    elif value["retained_until"] is not None:
        error(errors, f"{gate_id}: repository evidence must use null retained_until")
    return locator_kind, generated, retained


def validate_attestation(value: Any, reviewer: Any, gate_id: str, errors: list[str]) -> None:
    required = {"implementer", "reviewer", "competence", "statement"}
    if not isinstance(value, dict) or set(value) != required:
        error(errors, f"{gate_id}: attestation must identify implementer, reviewer, competence, and statement")
        return
    for key in required - {"competence"}:
        if not isinstance(value[key], str) or not value[key].strip():
            error(errors, f"{gate_id}: attestation.{key} must be a non-empty string")
    competence = value.get("competence")
    if (
        not isinstance(competence, list)
        or not competence
        or any(
            not isinstance(item, str) or item not in ALLOWED_REVIEW_COMPETENCIES
            for item in competence
        )
        or len(set(competence)) != len(competence)
    ):
        error(errors, f"{gate_id}: attestation.competence must list unique approved competencies")
    if value.get("reviewer") != reviewer:
        error(errors, f"{gate_id}: attestation reviewer must match evidence.reviewer")
    implementer_identity = str(value.get("implementer", "")).strip().casefold()
    reviewer_identity = str(value.get("reviewer", "")).strip().casefold()
    if implementer_identity == reviewer_identity:
        error(errors, f"{gate_id}: implementer cannot independently review their own evidence")
    if value.get("statement") != INDEPENDENT_REVIEW_STATEMENT:
        error(errors, f"{gate_id}: attestation statement must use the canonical independent-review text")


def validate_review_metadata(
    evidence: dict[str, Any],
    gate_id: str,
    errors: list[str],
) -> tuple[dt.datetime | None, dt.datetime | None]:
    """Validate a complete optional review record and return its timestamps."""
    review_fields = ("reviewer", "attestation", "reviewed_at", "expires_at")
    review_values = [evidence[key] for key in review_fields]
    if not all(review_values):
        return None, None
    validate_attestation(evidence["attestation"], evidence["reviewer"], gate_id, errors)
    reviewed = parse_date(evidence["reviewed_at"], f"{gate_id}.evidence.reviewed_at", errors)
    expiry = parse_date(evidence["expires_at"], f"{gate_id}.evidence.expires_at", errors)
    if reviewed and expiry and expiry <= reviewed:
        error(errors, f"{gate_id}: evidence expiry must follow review")
    if reviewed and reviewed > dt.datetime.now(tz=dt.timezone.utc):
        error(errors, f"{gate_id}: evidence review cannot be dated in the future")
    if expiry and expiry <= dt.datetime.now(tz=dt.timezone.utc):
        error(errors, f"{gate_id}: evidence review has expired")
    return reviewed, expiry


def table_statuses(path: Path, errors: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.lstrip().startswith("|"):
            continue
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
    for marker in (
        "check_slint_dependency",
        "check_dioxus_dependency",
        "check_diagnostic_runtime_dependency_graph",
        "is_slint_runtime_dependency",
        "is_dioxus_runtime_dependency",
        "tersa-slint-spike",
        "tersa-dioxus-spike",
    ):
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
        evidence_tier = gate["evidence_tier"]
        required_tier = gate["required_tier"]
        if not isinstance(evidence_tier, str) or evidence_tier not in tier_order:
            error(errors, f"{gate_id} has an unknown evidence tier")
        if not isinstance(required_tier, str) or required_tier not in tier_order:
            error(errors, f"{gate_id} has an unknown evidence tier")
        if gate_id in CANONICAL_REQUIRED_TIERS and required_tier != CANONICAL_REQUIRED_TIERS[gate_id]:
            error(errors, f"{gate_id}.required_tier does not match the reviewed minimum")
        if isinstance(gate["source_document"], str) and not (ROOT / gate["source_document"]).is_file():
            error(errors, f"{gate_id}.source_document does not exist")
        if gate["phase"] not in ("M0", "M1", "P1") or not gate_id.startswith(f"{gate['phase']}-"):
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
        has_commit = evidence["commit"] is not None
        has_artifact = evidence["artifact"] is not None
        if has_commit != has_artifact:
            error(errors, f"{gate_id}: evidence.commit and evidence.artifact must either both be null or both be present")
        if has_commit and (not isinstance(evidence["commit"], str) or not COMMIT.fullmatch(evidence["commit"])):
            error(errors, f"{gate_id}: evidence.commit must be an exact lowercase 40-character commit SHA")
        artifact_kind = None
        artifact_generated = None
        artifact_retained = None
        if has_artifact:
            artifact_kind, artifact_generated, artifact_retained = validate_artifact(
                evidence["artifact"], evidence["commit"], gate_id, errors
            )
        reviewed, expiry = validate_review_metadata(evidence, gate_id, errors)
        if reviewed and artifact_generated and reviewed < artifact_generated:
            error(errors, f"{gate_id}: evidence review cannot predate artifact generation")
        if (
            artifact_kind == "github-actions"
            and expiry
            and artifact_retained
            and expiry > artifact_retained
        ):
            error(errors, f"{gate_id}: evidence review cannot outlast GitHub Actions artifact retention")
        if evidence_tier == "simulator" and not has_artifact:
            error(errors, f"{gate_id}: simulator evidence requires a commit-bound artifact")
        if gate["status"] == "passed":
            evidence_rank = tier_order.get(evidence_tier, -1) if isinstance(evidence_tier, str) else -1
            required_rank = tier_order.get(required_tier, 99) if isinstance(required_tier, str) else 99
            if evidence_rank < required_rank:
                error(errors, f"{gate_id}: passed status does not meet required evidence tier")
            if gate["phase"] == "M1" or gate_id.startswith("M1-"):
                error(errors, f"{gate_id}: M1 cannot pass while ui_baseline_approved is false")
            if gate_id.startswith(("M0-SLINT-", "M0-DIOXUS-")):
                error(errors, f"{gate_id}: production UI cannot pass while ui_baseline_approved is false")
        signed_tier_claim = evidence_tier in (
            "device-signed",
            "distribution-signed",
        ) or (
            gate["status"] == "passed"
            and required_tier in ("device-signed", "distribution-signed")
        )
        if signed_tier_claim:
            for key in ("commit", "artifact", "reviewer", "attestation", "reviewed_at", "expires_at"):
                if not evidence[key]:
                    error(errors, f"{gate_id}: signed evidence requires evidence.{key}")
            if not isinstance(evidence["reviewer"], str) or not evidence["reviewer"].strip():
                error(errors, f"{gate_id}: signed evidence requires a named reviewer")
    if ids != set(CANONICAL_REQUIRED_TIERS):
        error(errors, "gate IDs must exactly match the reviewed canonical register")
    for gate_id, dependencies in CANONICAL_DEPENDENCIES.items():
        if gate_by_id.get(gate_id, {}).get("dependencies") != dependencies:
            error(errors, f"{gate_id}.dependencies do not match the reviewed dependency policy")
    for gate in gate_by_id.values():
        if not isinstance(gate["dependencies"], list) or not all(
            isinstance(item, str) for item in gate["dependencies"]
        ):
            continue
        for dependency in gate["dependencies"]:
            if dependency not in ids:
                error(errors, f"{gate['id']}: unknown dependency {dependency}")
            elif gate["phase"] == "P1" and gate_by_id[dependency]["phase"] != "P1":
                error(errors, f"{gate['id']}: P1 gates may depend only on P1 gates")
            elif gate["phase"] in ("M0", "M1") and gate_by_id[dependency]["phase"] == "P1":
                error(errors, f"{gate['id']}: M0 and M1 gates cannot depend on P1 gates")
            elif gate["status"] == "passed" and gate_by_id[dependency]["status"] != "passed":
                error(errors, f"{gate['id']}: passed gate has unresolved dependency {dependency}")
    p1_macos_gate_ids = ("P1-MACOS-001", "P1-MACOS-002", "P1-MACOS-003")
    p1_macos_guard = gate_by_id.get("P1-MACOS-003")
    if p1_macos_guard and p1_macos_guard["status"] == "passed":
        p1_macos_gates = [gate_by_id.get(gate_id) for gate_id in p1_macos_gate_ids]
        p1_macos_commits = {
            gate["evidence"].get("commit")
            if isinstance(gate, dict) and isinstance(gate.get("evidence"), dict)
            else None
            for gate in p1_macos_gates
        }
        if len(p1_macos_commits) != 1:
            error(
                errors,
                "P1-MACOS-003: aggregate pass requires P1-MACOS-001, P1-MACOS-002, "
                "and P1-MACOS-003 evidence commits to match",
            )
    table_ids: dict[str, str] = {}
    for document in UI_DOCUMENTS:
        document_ids = table_statuses(document, errors)
        for duplicate in set(table_ids) & set(document_ids):
            error(errors, f"duplicate UI table ID across documents: {duplicate}")
        table_ids.update(document_ids)
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
    now = dt.datetime.now(tz=dt.timezone.utc)
    artifact_generated_at = (now - dt.timedelta(days=2)).isoformat()
    artifact_retained_until = (now + dt.timedelta(days=87)).isoformat()
    reviewed_at = (now - dt.timedelta(days=1)).isoformat()
    expires_at = (now + dt.timedelta(days=30)).isoformat()
    valid_artifact = {
        "locator": f"github-actions://runs/1/artifacts/1/manifest.json#evidence-commit={'a' * 40}",
        "sha256": "b" * 64,
        "redacted": True,
        "generated_at": artifact_generated_at,
        "retained_until": artifact_retained_until,
    }
    valid_review = {
        "reviewer": "reviewer",
        "attestation": {
            "implementer": "implementer",
            "reviewer": "reviewer",
            "competence": ["apple-platform"],
            "statement": INDEPENDENT_REVIEW_STATEMENT,
        },
        "reviewed_at": reviewed_at,
        "expires_at": expires_at,
    }
    with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
        prose_fixture = Path(temporary) / "ui-prose-reference.md"
        prose_fixture.write_text(
            "The `M0-DIOXUS-013` criterion remains `open` in prose.\n"
            "| `M0-DIOXUS-013` | Physical-device accessibility | `open` |\n",
            encoding="utf-8",
        )
        prose_errors: list[str] = []
        prose_statuses = table_statuses(prose_fixture, prose_errors)
        if prose_errors or prose_statuses != {"M0-DIOXUS-013": "open"}:
            failures.append("backticked prose reference was parsed as a Markdown table row")
        prose_fixture.write_text(
            "| `M0-DIOXUS-013` | Missing status |\n",
            encoding="utf-8",
        )
        malformed_errors: list[str] = []
        table_statuses(prose_fixture, malformed_errors)
        if not any("malformed registered UI table row" in message for message in malformed_errors):
            failures.append("negative malformed Markdown register row unexpectedly passed")
    mutated = copy.deepcopy(data)
    simulator_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    simulator_gate["status"] = "diagnostic"
    simulator_gate["evidence_tier"] = "simulator"
    simulator_gate["evidence"].update(
        {
            "kind": "simulator-diagnostic",
            "commit": "a" * 40,
            "artifact": copy.deepcopy(valid_artifact),
        }
    )
    errors = validate(mutated)
    if errors:
        failures.append("valid simulator diagnostic fixture unexpectedly failed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"].update(
        {
            "commit": "a" * 40,
            "artifact": {**valid_artifact, "locator": "latest"},
        }
    )
    errors = validate(mutated)
    if not any("immutable, commit-bound evidence locator" in message for message in errors):
        failures.append("negative malformed diagnostic artifact mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"].update(
        {
            "commit": "a" * 40,
            "artifact": {
                **valid_artifact,
                "locator": f"repository://evidence/{'c' * 40}/manifest.json",
                "retained_until": None,
            },
        }
    )
    errors = validate(mutated)
    if not any("locator commit must exactly match evidence.commit" in message for message in errors):
        failures.append("negative commit/artifact mismatch mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"].update(
        {
            "commit": "A" * 40,
            "artifact": copy.deepcopy(valid_artifact),
        }
    )
    errors = validate(mutated)
    if not any("must be an exact lowercase 40-character commit SHA" in message for message in errors):
        failures.append("negative malformed non-null commit mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"]["artifact"] = copy.deepcopy(valid_artifact)
    errors = validate(mutated)
    if not any("must either both be null or both be present" in message for message in errors):
        failures.append("negative artifact-without-commit mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"]["commit"] = "a" * 40
    errors = validate(mutated)
    if not any("must either both be null or both be present" in message for message in errors):
        failures.append("negative commit-without-artifact mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    simulator_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    simulator_gate["status"] = "diagnostic"
    simulator_gate["evidence_tier"] = "simulator"
    simulator_gate["evidence"]["kind"] = "simulator-diagnostic"
    errors = validate(mutated)
    if not any("simulator evidence requires a commit-bound artifact" in message for message in errors):
        failures.append("negative simulator-without-artifact mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"].update(
        {
            "commit": "a" * 40,
            "artifact": copy.deepcopy(valid_artifact),
            **valid_review,
            "reviewed_at": (now - dt.timedelta(days=3)).isoformat(),
        }
    )
    errors = validate(mutated)
    if not any("review cannot predate artifact generation" in message for message in errors):
        failures.append("negative review-before-generation mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    diagnostic_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-001")
    diagnostic_gate["evidence"].update(
        {
            "commit": "a" * 40,
            "artifact": copy.deepcopy(valid_artifact),
            **valid_review,
            "expires_at": (now + dt.timedelta(days=88)).isoformat(),
        }
    )
    errors = validate(mutated)
    if not any("review cannot outlast GitHub Actions artifact retention" in message for message in errors):
        failures.append("negative review-expiry-after-retention mutation unexpectedly passed")
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
    if not any("signed evidence requires evidence.commit" in message for message in errors):
        failures.append("negative unsigned distribution-pass mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    ui_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-SLINT-011")
    ui_gate["status"] = "passed"
    ui_gate["evidence_tier"] = "device-signed"
    ui_gate["evidence"].update(
        {
            "kind": "device-run",
            "commit": "a" * 40,
            "artifact": copy.deepcopy(valid_artifact),
            "reviewer": "reviewer",
            "attestation": {
                "implementer": "implementer",
                "reviewer": "reviewer",
                "competence": ["apple-platform"],
                "statement": INDEPENDENT_REVIEW_STATEMENT,
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
            "artifact": copy.deepcopy(valid_artifact),
            "reviewer": "same-person",
            "attestation": {
                "implementer": " Same-Person ",
                "reviewer": "same-person",
                "competence": ["release-engineering"],
                "statement": INDEPENDENT_REVIEW_STATEMENT,
            },
            "reviewed_at": reviewed_at,
            "expires_at": expires_at,
        }
    )
    errors = validate(mutated)
    if not any("implementer cannot independently review" in message for message in errors):
        failures.append("negative self-review mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    cache_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    cache_gate["required_tier"] = "host"
    errors = validate(mutated)
    if not any("required_tier does not match" in message for message in errors):
        failures.append("negative required-tier downgrade unexpectedly passed")
    mutated = copy.deepcopy(data)
    cache_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    cache_gate["status"] = "passed"
    cache_gate["dependencies"] = ["M0-SLINT-006"]
    errors = validate(mutated)
    if not any("passed gate has unresolved dependency" in message for message in errors):
        failures.append("negative unresolved-dependency mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    cache_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    cache_gate["evidence_tier"] = []
    errors = validate(mutated)
    if not any("unknown evidence tier" in message for message in errors):
        failures.append("negative malformed-tier mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    cache_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    cache_gate["evidence_tier"] = "device-signed"
    errors = validate(mutated)
    if not any("signed evidence requires evidence.commit" in message for message in errors):
        failures.append("negative unbound signed-tier claim unexpectedly passed")
    mutated = copy.deepcopy(data)
    cache_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M0-CACHE-001")
    cache_gate["dependencies"] = None
    errors = validate(mutated)
    if not any("dependencies must be an array" in message for message in errors):
        failures.append("negative malformed-dependency mutation unexpectedly passed")
    errors = []
    validate_attestation(
        {
            "implementer": "implementer",
            "reviewer": "reviewer",
            "competence": [[]],
            "statement": INDEPENDENT_REVIEW_STATEMENT,
        },
        "reviewer",
        "SELF-TEST",
        errors,
    )
    if not any("approved competencies" in message for message in errors):
        failures.append("negative malformed-competence mutation unexpectedly passed")
    errors = []
    validate_artifact(
        {
            **valid_artifact,
            "locator": "latest",
        },
        "a" * 40,
        "SELF-TEST",
        errors,
    )
    if not any("immutable, commit-bound evidence locator" in message for message in errors):
        failures.append("negative mutable-artifact mutation unexpectedly passed")
    for locator, form in (
        (f"repository://evidence/{'c' * 40}/manifest.json", "repository"),
        (f"github-actions://runs/1/artifacts/1/manifest.json#evidence-commit={'c' * 40}", "GitHub Actions"),
    ):
        errors = []
        validate_artifact(
            {
                **valid_artifact,
                "locator": locator,
                "retained_until": (
                    artifact_retained_until if form == "GitHub Actions" else None
                ),
            },
            "a" * 40,
            "SELF-TEST",
            errors,
        )
        if not any("locator commit must exactly match evidence.commit" in message for message in errors):
            failures.append(f"negative {form} locator commit mismatch unexpectedly passed")
    errors = []
    validate_artifact(
        {
            **valid_artifact,
            "retained_until": (now + dt.timedelta(days=91)).isoformat(),
        },
        "a" * 40,
        "SELF-TEST",
        errors,
    )
    if not any("retention cannot exceed 90 days" in message for message in errors):
        failures.append("negative excessive artifact retention unexpectedly passed")
    errors = []
    validate_artifact(
        {
            **valid_artifact,
            "redacted": False,
        },
        "a" * 40,
        "SELF-TEST",
        errors,
    )
    if not any("evidence artifact must be explicitly redacted" in message for message in errors):
        failures.append("negative unredacted diagnostic artifact mutation unexpectedly passed")
    errors = []
    validate_artifact(
        {
            **valid_artifact,
            "generated_at": (now + dt.timedelta(days=1)).isoformat(),
            "retained_until": (now + dt.timedelta(days=89)).isoformat(),
        },
        "a" * 40,
        "SELF-TEST",
        errors,
    )
    if not any("artifact generation cannot be dated in the future" in message for message in errors):
        failures.append("negative future-dated artifact mutation unexpectedly passed")
    errors = []
    validate_artifact(
        {
            **valid_artifact,
            "locator": f"repository://evidence/{'a' * 40}/../../main/manifest.json",
            "retained_until": None,
        },
        "a" * 40,
        "SELF-TEST",
        errors,
    )
    if not any("repository artifact locator cannot contain dot path segments" in message for message in errors):
        failures.append("negative repository path-traversal mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    unknown_gate = copy.deepcopy(mutated["gates"][-1])
    unknown_gate["id"] = "M0-UNKNOWN-001"
    unknown_gate["phase"] = "M0"
    mutated["gates"].append(unknown_gate)
    errors = validate(mutated)
    if not any("exactly match the reviewed canonical register" in message for message in errors):
        failures.append("negative unknown-gate mutation unexpectedly passed")
    if validate(copy.deepcopy(data)):
        failures.append("legal M1-to-M0 dependency fixture unexpectedly failed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    p1_ui["id"] = "P2-MACOS-001"
    p1_ui["phase"] = "P2"
    errors = validate(mutated)
    if not any("not a stable gate ID" in message for message in errors):
        failures.append("negative P1 gate-ID grammar mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    p1_ui["required_tier"] = "device-signed"
    errors = validate(mutated)
    if not any("required_tier does not match" in message for message in errors):
        failures.append("negative P1 required-tier mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_guard = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-003")
    p1_guard["dependencies"] = ["P1-MACOS-002", "P1-MACOS-001"]
    errors = validate(mutated)
    if not any("dependencies do not match" in message for message in errors):
        failures.append("negative P1 canonical-dependency mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_guard = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-003")
    p1_guard["dependencies"] = ["M0-CACHE-001"]
    errors = validate(mutated)
    if not any("P1 gates may depend only on P1 gates" in message for message in errors):
        failures.append("negative P1-to-M0 dependency mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    m1_gate = next(gate for gate in mutated["gates"] if gate["id"] == "M1-UI-001")
    m1_gate["dependencies"] = ["P1-MACOS-001"]
    errors = validate(mutated)
    if not any("M0 and M1 gates cannot depend on P1 gates" in message for message in errors):
        failures.append("negative M1-to-P1 dependency mutation unexpectedly passed")

    def pass_p1_gate(gate: dict[str, Any]) -> None:
        gate["status"] = "passed"
        gate["evidence_tier"] = "distribution-signed"
        gate["evidence"].update(
            {
                "kind": "distribution",
                "commit": "a" * 40,
                "artifact": copy.deepcopy(valid_artifact),
                **copy.deepcopy(valid_review),
            }
        )

    mutated = copy.deepcopy(data)
    p1_guard = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-003")
    pass_p1_gate(p1_guard)
    errors = validate(mutated)
    if not any("passed gate has unresolved dependency" in message for message in errors):
        failures.append("negative unresolved P1 aggregate pass unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    pass_p1_gate(p1_ui)
    p1_ui["evidence"]["reviewer"] = None
    errors = validate(mutated)
    if not any("signed evidence requires evidence.reviewer" in message for message in errors):
        failures.append("negative incomplete P1 evidence mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    pass_p1_gate(p1_ui)
    p1_ui["evidence"]["artifact"]["redacted"] = False
    errors = validate(mutated)
    if not any("explicitly redacted" in message for message in errors):
        failures.append("negative unredacted P1 evidence mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    pass_p1_gate(p1_ui)
    p1_ui["evidence"]["expires_at"] = (now - dt.timedelta(days=1)).isoformat()
    errors = validate(mutated)
    if not any("evidence review has expired" in message for message in errors):
        failures.append("negative expired P1 evidence mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    pass_p1_gate(p1_ui)
    p1_ui["evidence"].update(
        {
            "reviewer": "implementer",
            "attestation": {
                **p1_ui["evidence"]["attestation"],
                "reviewer": "implementer",
            },
        }
    )
    errors = validate(mutated)
    if not any("implementer cannot independently review" in message for message in errors):
        failures.append("negative P1 self-review mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    p1_ui = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-001")
    pass_p1_gate(p1_ui)
    p1_ui["evidence"]["artifact"]["locator"] = (
        f"github-actions://runs/1/artifacts/1/manifest.json#evidence-commit={'c' * 40}"
    )
    errors = validate(mutated)
    if not any("locator commit must exactly match evidence.commit" in message for message in errors):
        failures.append("negative P1 commit/artifact mismatch mutation unexpectedly passed")
    mutated = copy.deepcopy(data)
    for gate_id in ("P1-MACOS-001", "P1-MACOS-002", "P1-MACOS-003"):
        pass_p1_gate(next(gate for gate in mutated["gates"] if gate["id"] == gate_id))
    errors = validate(mutated)
    if errors:
        failures.append("legal P1 pass sequence with ui_baseline_approved=false unexpectedly failed")
    mutated = copy.deepcopy(data)
    for gate_id in ("P1-MACOS-001", "P1-MACOS-002", "P1-MACOS-003"):
        pass_p1_gate(next(gate for gate in mutated["gates"] if gate["id"] == gate_id))
    p1_release = next(gate for gate in mutated["gates"] if gate["id"] == "P1-MACOS-002")
    p1_release["evidence"]["commit"] = "c" * 40
    p1_release["evidence"]["artifact"]["locator"] = (
        f"github-actions://runs/1/artifacts/1/manifest.json#evidence-commit={'c' * 40}"
    )
    errors = validate(mutated)
    if not any("aggregate pass requires" in message for message in errors):
        failures.append("negative P1 aggregate commit-mismatch mutation unexpectedly passed")
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
