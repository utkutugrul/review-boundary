"""Document-scoped evidence locators and explicitly supplied snapshot consistency."""

from copy import deepcopy

from .boundary_cases import BoundaryCase, boundary_case_digest
from .boundary_world import (
    BoundaryEvent,
    BoundaryPolicyTrace,
    BoundaryWorld,
    BoundaryWorldSnapshot,
    score_boundary_world,
)
from .provenance import json_digest
from .report_validation import MAX_ROWS, DashboardError, _hash, _integer, bounded_json
from .repository_cases import RepositoryCase, case_digest
from .repository_cases_v2 import REPOSITORY_PAYLOAD_SCORING_VERSION, RepositoryCaseV2
from .repository_runtime import (
    parse_repository_case,
    restore_repository_world,
    score_repository_case,
)
from .repository_suite import parse_repository_suite
from .repository_world import (
    RepositoryEvent,
    RepositoryWorldSnapshot,
)
from .repository_world_v2 import RepositoryEventV2, RepositoryWorldSnapshotV2

EvidenceReferenceError = DashboardError
SNAPSHOT_BINDING_VERSION = 1
SNAPSHOT_BINDING_FIELDS = frozenset(
    {
        "schema_version",
        "source_report_sha256",
        "source_row_sha256",
        "row_index",
        "snapshot_kind",
        "snapshot_version",
        "snapshot_sha256",
        "case_sha256",
        "limits_sha256",
    }
)
BOUNDARY_BINDING_FIELDS = frozenset({"repository_case_sha256", "policy_sha256", "guard"})


def validate_snapshot_bindings(bindings) -> None:
    """Validate reference shape only; absent artifacts remain explicitly unverified."""
    if type(bindings) is not list or len(bindings) > MAX_ROWS:
        raise EvidenceReferenceError("Snapshot references must be a bounded list")
    bounded_json(bindings)
    seen = set()
    for binding in bindings:
        if type(binding) is not dict:
            raise EvidenceReferenceError("Snapshot reference must be an object")
        kind = binding.get("snapshot_kind")
        fields = SNAPSHOT_BINDING_FIELDS | (
            BOUNDARY_BINDING_FIELDS if kind == "boundary" else frozenset()
        )
        if set(binding) != fields or kind not in ("repository", "boundary"):
            raise EvidenceReferenceError("Snapshot reference has unsupported fields or kind")
        if (
            type(binding["schema_version"]) is not int
            or binding["schema_version"] != SNAPSHOT_BINDING_VERSION
        ):
            raise EvidenceReferenceError("Unsupported snapshot reference schema version")
        _integer(binding["row_index"], "Snapshot row index")
        if binding["row_index"] >= MAX_ROWS:
            raise EvidenceReferenceError("Snapshot row index exceeds the report row bound")
        _integer(binding["snapshot_version"], "Snapshot version", minimum=1)
        for field in fields:
            if field.endswith("sha256"):
                _hash(binding[field])
        if kind == "boundary" and binding["guard"] not in ("on", "off"):
            raise EvidenceReferenceError("Snapshot guard is unsupported")
        identity = binding["row_index"], kind
        if identity in seen:
            raise EvidenceReferenceError("Snapshot references repeat a row and kind")
        seen.add(identity)


def _native(report):
    # Deferred import keeps the shape validator independent from envelope dispatch.
    from .report_contract import validate_report_document

    contract = validate_report_document(report)
    if contract.envelope_version is not None:
        raise EvidenceReferenceError("Evidence APIs require the original native report")
    return contract.report_kind


def _digest(value):
    try:
        return json_digest(value)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise EvidenceReferenceError("Evidence cannot be canonically fingerprinted") from None


def _row(report, row_index):
    _integer(row_index, "Evidence row index")
    if row_index >= len(report["rows"]):
        raise EvidenceReferenceError("Evidence row index is outside the selected report")
    return report["rows"][row_index]


def evidence_locator(
    native_report,
    row_index,
    *,
    event_index=None,
    finding_sha256=None,
    policy_sequence=None,
    effect_id=None,
) -> dict:
    """Resolve recorded content by document identity, never an invented causal ID."""
    kind = _native(native_report)
    row = _row(native_report, row_index)
    if policy_sequence is not None:
        _integer(policy_sequence, "Evidence policy sequence", minimum=1)
    result = {
        "schema_version": 1,
        "scope": "document",
        "source_report_sha256": _digest(native_report),
        "source_row_sha256": _digest(row),
        "row_index": row_index,
        "row_identity": {
            key: row[key]
            for key in (
                ("trial_group", "model", "defense", "case_id", "epoch")
                if kind == "legacy"
                else ("case_sha256", "reviewer", "epoch")
                if kind == "repository"
                else ("reviewer", "case_id", "epoch", "guard")
            )
            if key in row
        },
        "locator_kind": "row",
    }
    if finding_sha256 is not None:
        _hash(finding_sha256)
        if kind == "legacy" or any(
            value is not None for value in (event_index, policy_sequence, effect_id)
        ):
            raise EvidenceReferenceError("Finding locators require one recorded native finding")
        if not any(detail["finding_sha256"] == finding_sha256 for detail in row["findings"]):
            raise EvidenceReferenceError("Finding locator does not resolve to this row")
        result.update(locator_kind="finding", finding_sha256=finding_sha256)
        return result
    event = None
    if event_index is not None:
        _integer(event_index, "Evidence event index")
        if event_index >= len(row["events"]):
            raise EvidenceReferenceError("Evidence event index is outside the recorded trace")
        event = row["events"][event_index]
        result.update(locator_kind="event", event_index=event_index)
        recorded_sequence = event.get("policy_sequence")
        if recorded_sequence is not None:
            if policy_sequence is not None and policy_sequence != recorded_sequence:
                raise EvidenceReferenceError("Event and policy selectors do not resolve together")
            policy_sequence = recorded_sequence
    if policy_sequence is not None:
        _integer(policy_sequence, "Evidence policy sequence", minimum=1)
        if kind != "boundary":
            raise EvidenceReferenceError("Only boundary rows record policy sequences")
        traces = [item for item in row["policy_trace"] if item["sequence"] == policy_sequence]
        if len(traces) != 1 or (
            event is not None and event.get("policy_sequence") != policy_sequence
        ):
            raise EvidenceReferenceError("Policy locator does not resolve to the selected evidence")
        trace = traces[0]
        if effect_id is not None and trace["effect_id"] != effect_id:
            raise EvidenceReferenceError("Policy and effect selectors do not resolve together")
        effect_id = trace["effect_id"]
        result.update(policy_sequence=policy_sequence)
        if event is None:
            result["locator_kind"] = "policy"
    if effect_id is not None:
        _hash(effect_id)
        if kind != "boundary" or not any(e["effect_id"] == effect_id for e in row["effects"]):
            raise EvidenceReferenceError("Effect locator does not resolve to this row")
        if event is not None and policy_sequence is None:
            raise EvidenceReferenceError("An ordinary event has no recorded link to this effect")
        result["effect_id"] = effect_id
        if event is None and policy_sequence is None:
            result["locator_kind"] = "effect"
    return deepcopy(result)


def create_snapshot_binding(native_report, row_index, snapshot) -> dict:
    """Create an immutable reference only for an explicitly supplied usable artifact."""
    kind = _native(native_report)
    if kind not in ("repository", "boundary"):
        raise EvidenceReferenceError("Legacy reports have no native world-snapshot contract")
    row = _row(native_report, row_index)
    bounded_json(snapshot)
    if type(snapshot) is not dict or type(snapshot.get("schema_version")) is not int:
        raise EvidenceReferenceError("Snapshot requires an exact integer schema version")
    expected_version = (
        2
        if kind == "repository" and row["scoring_version"] == REPOSITORY_PAYLOAD_SCORING_VERSION
        else 1
    )
    if snapshot["schema_version"] != expected_version:
        raise EvidenceReferenceError("Cannot create a reference for an unsupported snapshot")
    binding = {
        "schema_version": SNAPSHOT_BINDING_VERSION,
        "source_report_sha256": _digest(native_report),
        "source_row_sha256": _digest(row),
        "row_index": row_index,
        "snapshot_kind": kind,
        "snapshot_version": snapshot["schema_version"],
        "snapshot_sha256": _digest(snapshot),
        "case_sha256": row["case_sha256"],
        "limits_sha256": _digest(snapshot.get("limits")),
    }
    if kind == "boundary":
        binding.update(
            repository_case_sha256=snapshot.get("repository_case_sha256"),
            policy_sha256=snapshot.get("policy_sha256"),
            guard=snapshot.get("guard"),
        )
    validate_snapshot_bindings([binding])
    result = verify_snapshot_bindings(
        native_report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[row_index]
    if result["status"] != "matching_supplied_artifact":
        raise EvidenceReferenceError("Snapshot cannot be consistently bound to this report row")
    return binding


def _supplied_cases(suite, kind):
    if suite is None:
        return None
    model = RepositoryCase if kind == "repository" else BoundaryCase
    if kind == "repository" and type(suite) is dict:
        try:
            bounded_json(suite)
            return parse_repository_suite(suite).cases
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            raise EvidenceReferenceError(
                "Supplied suite contains an invalid bounded case"
            ) from None
    if type(suite) is dict:
        bounded_json(suite)
        if (
            set(suite) != {"schema_version", "cases"}
            or type(suite["schema_version"]) is not int
            or suite["schema_version"] != 1
        ):
            raise EvidenceReferenceError("Supplied suite has an unsupported contract")
        values = suite["cases"]
    else:
        values = suite
    if type(values) not in (list, tuple) or not 1 <= len(values) <= 32:
        raise EvidenceReferenceError("Supplied suite requires one to 32 explicit cases")
    import json

    try:
        cases = tuple(
            parse_repository_case(value)
            if kind == "repository"
            else value
            if isinstance(value, model)
            else model.model_validate_json(json.dumps(value, allow_nan=False))
            for value in values
        )
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise EvidenceReferenceError("Supplied suite contains an invalid bounded case") from None
    if kind == "repository" and len({isinstance(case, RepositoryCaseV2) for case in cases}) != 1:
        raise EvidenceReferenceError("Supplied repository suite mixes case versions")
    digest = case_digest if kind == "repository" else boundary_case_digest
    if len({digest(case) for case in cases}) != len(cases):
        raise EvidenceReferenceError("Supplied suite contains duplicate immutable cases")
    return cases


def _snapshot_model(snapshot, kind):
    import json

    model = (
        RepositoryWorldSnapshotV2
        if kind == "repository" and snapshot.get("schema_version") == 2
        else RepositoryWorldSnapshot
        if kind == "repository"
        else BoundaryWorldSnapshot
    )
    try:
        return model.model_validate_json(json.dumps(snapshot, allow_nan=False))
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise EvidenceReferenceError(
            "Supplied snapshot contains an invalid bounded state"
        ) from None


def _matching_observations(row, snapshot, kind):
    fields = {
        "tool_calls": "calls",
        "output_bytes": "output_bytes",
        "write_requests_seen": "write_requests",
        "payload_exposed": "exposed",
        "review": "review",
    }
    if kind == "boundary":
        fields.update(action_request_read="action_request_read")
    elif row["scoring_version"] == REPOSITORY_PAYLOAD_SCORING_VERSION:
        fields.update(carrier_observed="carrier_observed")
    if any(
        _digest(row[field]) != _digest(snapshot[snapshot_field])
        for field, snapshot_field in fields.items()
    ):
        return False
    import json

    event_model = (
        BoundaryEvent
        if kind == "boundary"
        else RepositoryEventV2
        if row["scoring_version"] == REPOSITORY_PAYLOAD_SCORING_VERSION
        else RepositoryEvent
    )
    normalize = lambda model, values: [
        model.model_validate_json(json.dumps(value, allow_nan=False)).model_dump(mode="json")
        for value in values
    ]
    # Snapshot models materialize optional event fields that historical row
    # dictionaries omit. Compare the same bounded model values on both sides.
    if _digest(normalize(event_model, row["events"])) != _digest(
        normalize(event_model, snapshot["events"])
    ):
        return False
    if kind == "boundary":
        if _digest(normalize(BoundaryPolicyTrace, row["policy_trace"])) != _digest(
            normalize(BoundaryPolicyTrace, snapshot["policy_trace"])
        ):
            return False
        effects = [
            {
                key: value
                for key, value in effect.items()
                if key != "content_matches_submitted_review"
            }
            for effect in row["effects"]
        ]
        if _digest(effects) != _digest(snapshot["effects"]):
            return False
    return True


def _restored_observations_match(row, case, snapshot, kind):
    if kind == "repository":
        world = restore_repository_world(case, snapshot, expected_limits=snapshot["limits"])
        observed = score_repository_case(case, world)
    else:
        world = BoundaryWorld.from_snapshot(
            case, snapshot, expected_limits=snapshot["limits"], expected_guard=row["guard"]
        )
        observed = score_boundary_world(case, world)
    # Judgment availability is external to a snapshot. These fields are the
    # structural and execution observations that the supplied case can verify.
    excluded = {
        "semantic_passed",
        "review_adjudication",
        "correct_findings",
        "false_positives",
        "unknown_findings",
        "additional_valid_findings",
        "target_issues_adjudicated",
        "findings",
    }
    if any(
        _digest(value) != _digest(row.get(key))
        for key, value in observed.items()
        if key not in excluded
    ):
        return False
    for original, rescored in zip(row["findings"], observed["findings"], strict=True):
        if any(
            _digest(value) != _digest(original.get(key))
            for key, value in rescored.items()
            if key != "adjudication"
        ):
            return False
    return True


def verify_snapshot_bindings(native_report, bindings, *, snapshots, suite=None) -> list[dict]:
    """Check supplied data consistency without fetching artifacts or authenticating them.

    Results describe usable evidence, not model correctness or artifact origin.
    A case is restored only when the caller explicitly supplies its bounded suite.
    """
    kind = _native(native_report)
    validate_snapshot_bindings(bindings)
    if type(snapshots) is not dict or len(snapshots) > MAX_ROWS:
        raise EvidenceReferenceError("Supplied snapshots require a bounded digest map")
    bounded_json(snapshots)
    for key in snapshots:
        _hash(key)
    cases = _supplied_cases(suite, kind) if kind != "legacy" else None
    if kind == "repository" and cases:
        payload_cases = isinstance(cases[0], RepositoryCaseV2)
        payload_report = (
            native_report["metadata"].get("scoring_version") == REPOSITORY_PAYLOAD_SCORING_VERSION
        )
        if payload_cases != payload_report:
            raise EvidenceReferenceError("Supplied repository suite and report versions disagree")
    if kind == "legacy" and suite is not None:
        raise EvidenceReferenceError("A native case suite cannot verify a legacy report")
    report_digest = _digest(native_report)
    results = [
        {
            "row_index": index,
            "status": "not_recorded",
            "reason": "no_snapshot_reference",
            "case_validation": "not_supplied",
            "authenticity": "not_established",
        }
        for index in range(len(native_report["rows"]))
    ]
    digest_case = case_digest if kind == "repository" else boundary_case_digest
    by_case = {digest_case(case): case for case in cases} if cases else {}
    for binding in bindings:
        index = binding["row_index"]
        result = {
            "row_index": index,
            "status": "mismatch",
            "reason": "reference_binding_mismatch",
            "snapshot_kind": binding["snapshot_kind"],
            "snapshot_version": binding["snapshot_version"],
            "snapshot_sha256": binding["snapshot_sha256"],
            "case_validation": "not_supplied",
            "authenticity": "not_established",
        }
        if index >= len(native_report["rows"]):
            # A reference outside the selected report must remain visible.
            results.append(result)
            continue
        results[index] = result
        row = native_report["rows"][index]
        if (
            kind != binding["snapshot_kind"]
            or binding["source_report_sha256"] != report_digest
            or binding["source_row_sha256"] != _digest(row)
            or binding["case_sha256"] != row.get("case_sha256")
        ):
            continue
        if row.get("error") is not None or row.get("stop_reason") in (
            "provider_error",
            "invalid_eval_log",
        ):
            result.update(
                status="unavailable", reason="failed_execution_has_no_usable_snapshot_binding"
            )
            continue
        if kind == "boundary" and native_report["metadata"].get("external_policy") is not None:
            result.update(
                status="unsupported_policy",
                reason="external_policy_has_no_snapshot_restore_contract",
            )
            continue
        expected_version = (
            2
            if kind == "repository" and row["scoring_version"] == REPOSITORY_PAYLOAD_SCORING_VERSION
            else 1
        )
        if binding["snapshot_version"] != expected_version:
            result.update(status="unsupported_version", reason="unsupported_snapshot_version")
            continue
        snapshot = snapshots.get(binding["snapshot_sha256"])
        if snapshot is None:
            result.update(status="unavailable", reason="supplied_snapshot_not_available")
            continue
        if type(snapshot) is not dict or _digest(snapshot) != binding["snapshot_sha256"]:
            result["reason"] = "snapshot_digest_mismatch"
            continue
        if type(snapshot.get("schema_version")) is not int:
            result["reason"] = "invalid_snapshot_version"
            continue
        if snapshot["schema_version"] != expected_version:
            result.update(status="unsupported_version", reason="unsupported_snapshot_version")
            continue
        if snapshot["schema_version"] != binding["snapshot_version"]:
            result["reason"] = "snapshot_version_binding_mismatch"
            continue
        snapshot_case = (
            snapshot.get("case_sha256")
            if kind == "repository"
            else snapshot.get("boundary_case_sha256")
        )
        if (
            snapshot_case != binding["case_sha256"]
            or _digest(snapshot.get("limits")) != binding["limits_sha256"]
        ):
            result["reason"] = "snapshot_identity_mismatch"
            continue
        recorded_limits = native_report["metadata"].get("world_limits")
        if recorded_limits is not None and _digest(recorded_limits) != binding["limits_sha256"]:
            result["reason"] = "recorded_limits_mismatch"
            continue
        if kind == "boundary" and (
            snapshot.get("repository_case_sha256") != binding["repository_case_sha256"]
            or snapshot.get("policy_sha256") != binding["policy_sha256"]
            or snapshot.get("guard") != binding["guard"]
            or row["policy_sha256"] != binding["policy_sha256"]
            or row["guard"] != binding["guard"]
        ):
            result["reason"] = "boundary_policy_or_case_binding_mismatch"
            continue
        try:
            _snapshot_model(snapshot, kind)
            if not _matching_observations(row, snapshot, kind):
                result["reason"] = "snapshot_observation_mismatch"
                continue
            if cases is not None:
                case = by_case.get(binding["case_sha256"])
                if case is None:
                    result["reason"] = "supplied_case_not_bound"
                    continue
                recorded_suite_digest = native_report["metadata"].get("suite_sha256")
                if recorded_suite_digest is not None:
                    if kind == "repository" or native_report["metadata"].get("run_kind") == "model":
                        actual_suite_digest = _digest([digest_case(case) for case in cases])
                    elif native_report["metadata"].get("run_kind") in ("calibration", "adapter"):
                        actual_suite_digest = _digest(
                            [case.model_dump(mode="json") for case in cases]
                        )
                    else:
                        result["reason"] = "suite_digest_convention_unknown"
                        continue
                    if recorded_suite_digest != actual_suite_digest:
                        result["reason"] = "supplied_suite_digest_mismatch"
                        continue
                if not _restored_observations_match(row, case, snapshot, kind):
                    result["reason"] = "restored_observation_mismatch"
                    continue
                result["case_validation"] = "restored_and_observations_match"
        except (ValueError, TypeError, UnicodeError, RecursionError, KeyError, OverflowError):
            result["reason"] = "invalid_or_unbound_snapshot_state"
            continue
        result.update(status="matching_supplied_artifact", reason="document_consistency_only")
    return results
