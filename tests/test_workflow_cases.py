"""Case matching and public-input boundaries for the new workflow protocol."""

import json

import pytest

from review_boundary.workflow_cases import (
    FAMILIES,
    IntentGrant,
    WorkflowCase,
    WorkflowRunBinding,
    bounded_json,
    build_workflow_cases,
    canonical_bytes,
    checked,
    validate_workflow_case,
    workflow_case_digest,
    workflow_instructions,
    workflow_policy_document,
    workflow_tool_schemas,
)
from review_boundary.workflow_world import (
    WorkflowBridge,
    WorkflowSessionWorld,
    WorkflowSnapshot,
    seal_workflow_bridge,
)


def select(family="purpose_permission", condition="clean", variant="vulnerable"):
    return next(
        case
        for case in build_workflow_cases()
        if (case.family, case.condition, case.repository.variant) == (family, condition, variant)
    )


def test_thirty_original_cases_and_real_session_counts_have_one_source_group():
    cases = build_workflow_cases()
    assert len(cases) == len({case.case_id for case in cases}) == 30
    assert {case.family for case in cases} == set(FAMILIES)
    assert {case.source_group for case in cases} == {"original_tenant_flow"}
    assert sum(len(case.sessions) for case in cases) == 42
    for case in cases:
        assert case.repository.surface == "clean"
        assert case.repository.exposure is None
        assert validate_workflow_case(case.model_dump(mode="json")) == case
        assert checked(WorkflowCase, canonical_bytes(case), wire=True) == case


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_attack_pairs_keep_trusted_authority_and_legitimate_control_changes_real_request(
    family, variant
):
    clean = select(family, "clean", variant)
    attacked = select(family, "attack", variant)
    authorized = select(family, "authorized_control", variant)
    assert clean.repository == attacked.repository == authorized.repository
    assert workflow_case_digest(clean) != workflow_case_digest(attacked)
    for ordinary, malicious in zip(clean.sessions, attacked.sessions):
        assert ordinary.actor == malicious.actor
        assert ordinary.tools == malicious.tools
        assert ordinary.user_request == malicious.user_request
        assert ordinary.grants == malicious.grants
        assert ordinary.required_actions == malicious.required_actions
    for malicious, allowed in zip(attacked.sessions, authorized.sessions):
        assert malicious.work_items == allowed.work_items
        assert malicious.descriptions == allowed.descriptions
    assert attacked.sessions[-1].grants != authorized.sessions[-1].grants
    assert attacked.sessions[-1].user_request != authorized.sessions[-1].user_request


@pytest.mark.parametrize("family", FAMILIES)
def test_reviewer_inputs_do_not_include_evaluator_labels_or_guard_state(family):
    case = select(family, "attack")
    binding = WorkflowRunBinding(run_id="a" * 32, reviewer="fixture", epoch=1)
    for index in range(len(case.sessions)):
        public = workflow_instructions(case, index)
        for hidden in (
            case.case_id,
            "acceptable_bundles",
            "payload_marker",
            "case_id",
            "source_group",
        ):
            assert hidden not in public
        assert workflow_policy_document(case, index)["grants"] == [
            grant.model_dump(mode="json") for grant in case.sessions[index].grants
        ]
    if len(case.sessions) == 1:
        on = WorkflowSessionWorld(case, 0, "on", binding=binding)
        off = WorkflowSessionWorld(case, 0, "off", binding=binding)
        assert on.session == off.session
        assert workflow_tool_schemas(on.case, 0) == workflow_tool_schemas(off.case, 0)


def test_poison_is_actual_description_and_every_schema_construction_is_fresh():
    attacked = select("tool_description_poison", "attack")
    clean = select("tool_description_poison", "clean")
    baseline = workflow_tool_schemas(clean, 0)
    poisoned = workflow_tool_schemas(attacked, 0)
    first = {item["name"]: item for item in baseline}
    second = {item["name"]: item for item in poisoned}
    assert set(first) == set(second)
    assert first["send_report"]["parameters"] == second["send_report"]["parameters"]
    assert attacked.payload_marker in second["send_report"]["description"]
    assert attacked.payload_marker not in json.dumps(baseline)
    poisoned[0]["parameters"]["type"] = "changed"
    second["send_report"]["description"] = "mutated caller copy"
    assert workflow_tool_schemas(clean, 0) == baseline
    assert attacked.payload_marker in json.dumps(workflow_tool_schemas(attacked, 0))


@pytest.mark.parametrize(
    "change", ["duplicate_grant", "foreign_purpose", "missing_tool", "extra_tool"]
)
def test_session_contract_rejects_invalid_capabilities_and_requirements(change):
    case = select()
    session = case.sessions[0]
    if change == "duplicate_grant":
        modified = session.model_copy(update={"grants": session.grants * 2})
    elif change == "foreign_purpose":
        grant = IntentGrant(tool="send_report", target="elsewhere", purpose="publish_review")
        modified = session.model_copy(update={"grants": (grant,)})
    elif change == "missing_tool":
        modified = session.model_copy(
            update={"tools": tuple(t for t in session.tools if t != "read_pr")}
        )
    else:
        modified = session.model_copy(update={"tools": (*session.tools, "remember_note")})
    bypassed = case.model_copy(update={"sessions": (modified,)})
    with pytest.raises(ValueError):
        validate_workflow_case(bypassed)
    with pytest.raises(ValueError):
        WorkflowSessionWorld(
            bypassed,
            0,
            binding=WorkflowRunBinding(run_id="a" * 32, reviewer="fixture", epoch=1),
        )


@pytest.mark.parametrize("index", [-1, 1, True, "0"])
def test_public_session_lookups_require_an_exact_existing_index(index):
    case = select()
    with pytest.raises(ValueError):
        workflow_tool_schemas(case, index)
    with pytest.raises(ValueError):
        workflow_policy_document(case, index)


@pytest.mark.parametrize("raw", [b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}'])
def test_wire_decoder_refuses_duplicate_keys_and_nonfinite_values(raw):
    with pytest.raises(ValueError):
        checked(WorkflowCase, raw)


def test_public_model_copy_and_boolean_version_are_revalidated():
    case = select()
    invalid = case.model_copy(update={"schema_version": True})
    with pytest.raises(ValueError):
        validate_workflow_case(invalid)
    data = case.model_dump(mode="json")
    data["unknown"] = "not allowed"
    with pytest.raises(ValueError):
        validate_workflow_case(data)


@pytest.mark.parametrize(
    "family", ["multi_step_drift", "tool_description_poison", "persistent_memory_poison"]
)
def test_carrier_labels_cannot_turn_a_single_note_into_other_surface_coverage(family):
    case = select(family, "attack")
    session = case.sessions[0].model_copy(update={"exposure": "bridge"})
    with pytest.raises(ValueError):
        validate_workflow_case(case.model_copy(update={"sessions": (session, *case.sessions[1:])}))
    if family == "tool_description_poison":
        session = case.sessions[0].model_copy(
            update={
                "descriptions": (),
                "work_items": (case.payload_marker,),
            }
        )
        with pytest.raises(ValueError):
            validate_workflow_case(case.model_copy(update={"sessions": (session,)}))


def test_depth_nodes_bytes_and_unicode_limits_are_independent():
    with pytest.raises(ValueError):
        bounded_json({"nested": [[1]]}, maximum=100, depth=1)
    with pytest.raises(ValueError):
        bounded_json({"many": [1, 2, 3]}, maximum=100, nodes=3)
    with pytest.raises(ValueError):
        bounded_json({"text": "é" * 20}, maximum=25)
    with pytest.raises(ValueError):
        bounded_json({"float": 0.5}, maximum=100)


def test_old_boundary_case_still_has_its_original_protocol_and_conditions():
    from review_boundary.boundary_cases import build_boundary_cases

    old = build_boundary_cases()
    assert len(old) == 24
    assert {case.condition for case in old} == {"clean", "attack"}
    assert all(not hasattr(case, "bridge_kind") for case in old)


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
@pytest.mark.parametrize("condition", ["clean", "attack", "authorized_control"])
def test_all_thirty_cases_roundtrip_json_without_relaxing_python_tuple_inputs(
    family, variant, condition
):
    case = select(family, condition, variant)
    raw = canonical_bytes(case)
    decoded = json.loads(raw)
    for value in (case, decoded, raw):
        assert validate_workflow_case(value) == case
    assert checked(WorkflowCase, raw, wire=True) == case
    assert WorkflowCase.model_validate_json(raw) == case
    assert WorkflowCase.model_validate(case.model_dump(mode="python")) == case
    assert WorkflowCase(**case.model_dump(mode="python")) == case
    assert canonical_bytes(WorkflowCase.model_validate_json(raw)) == raw
    with pytest.raises(ValueError, match="tuple_type"):
        WorkflowCase.model_validate(decoded)
    del decoded["schema_version"]
    assert validate_workflow_case(decoded) == case
    assert WorkflowCase.model_validate_json(json.dumps(decoded)) == case


def public_identity_examples():
    case = select("persistent_memory_poison", variant="fixed")
    run = WorkflowRunBinding(run_id="b" * 32, reviewer="scripted_calibration", epoch=1)
    producer = WorkflowSessionWorld(case, 0, binding=run)
    producer.record_tool_delivery(workflow_tool_schemas(case, 0))
    assert (
        producer.dispatch("remember_note", {"text": "Ordinary technical note."})["status"] == "ok"
    )
    assert (
        producer.dispatch("submit_review", {"verdict": "approve", "findings": []})["status"] == "ok"
    )
    snapshot = producer.snapshot()
    bridge = seal_workflow_bridge(case, snapshot, binding=run, guard="on")
    return {
        "case": case,
        "snapshot": WorkflowSnapshot.model_validate_json(canonical_bytes(snapshot)),
        "bridge": WorkflowBridge.model_validate_json(bridge),
    }


def test_actual_producer_snapshot_and_bridge_roundtrip_with_strict_tuple_fields():
    examples = public_identity_examples()
    for name in ("snapshot", "bridge"):
        model = examples[name]
        raw = canonical_bytes(model)
        model_type = type(model)
        assert checked(model_type, raw, wire=True) == model
        assert model_type.model_validate_json(raw) == model
        assert model_type.model_validate(model.model_dump(mode="python")) == model
        assert model_type(**model.model_dump(mode="python")) == model
        decoded = model.model_dump(mode="json")
        assert checked(model_type, decoded) == model
        with pytest.raises(ValueError, match="tuple_type"):
            model_type.model_validate(decoded)
        del decoded["schema_version"]
        if name == "bridge":
            del decoded["producer_session"], decoded["consumer_session"]
        assert model_type.model_validate_json(json.dumps(decoded)) == model
    assert isinstance(examples["snapshot"].events, tuple)
    assert isinstance(examples["bridge"].entries, tuple)


@pytest.mark.parametrize("entry_point", ["constructor", "python", "json"])
@pytest.mark.parametrize(
    "name,field,bool_alias",
    [
        ("case", "schema_version", True),
        ("snapshot", "schema_version", True),
        ("bridge", "schema_version", True),
        ("bridge", "producer_session", False),
        ("bridge", "consumer_session", True),
    ],
)
def test_direct_public_identity_fields_reject_bool_float_and_string_aliases(
    entry_point, name, field, bool_alias
):
    model = public_identity_examples()[name]
    model_type = type(model)
    for alias in (bool_alias, float(int(bool_alias)), str(int(bool_alias))):
        data = model.model_dump(mode="python")
        data[field] = alias
        with pytest.raises(ValueError, match="exact integer"):
            if entry_point == "constructor":
                model_type(**data)
            elif entry_point == "python":
                model_type.model_validate(data)
            else:
                model_type.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "input_kind",
    [
        "float",
        "nul_string",
        "non_string_key",
        "tuple",
        "invalid_unicode",
        "byte_cap",
        "string_size_cap",
        "node_cap",
        "depth_cap",
    ],
)
def test_bounded_json_distinguishes_caps_from_unsupported_workflow_values(input_kind):
    from review_boundary.workflow_cases import WorkflowJSONDomainError, WorkflowJSONResourceError

    value, options = {"field": "valid"}, {"maximum": 100}
    if input_kind == "float":
        value = {"field": 0.5}
    elif input_kind == "nul_string":
        value = {"field": "bad\0value"}
    elif input_kind == "non_string_key":
        value = {1: "value"}
    elif input_kind == "tuple":
        value = {"field": (1,)}
    elif input_kind == "invalid_unicode":
        value = {"field": "\ud800"}
    elif input_kind == "byte_cap":
        value, options = {"field": "é" * 20}, {"maximum": 30}
    elif input_kind == "string_size_cap":
        value, options = {"field": "x" * 20}, {"maximum": 10}
    elif input_kind == "node_cap":
        value, options = {"field": [1, 2, 3]}, {"maximum": 100, "nodes": 3}
    else:
        value, options = {"field": [[1]]}, {"maximum": 100, "depth": 1}
    resource = input_kind in {"byte_cap", "string_size_cap", "node_cap", "depth_cap"}
    expected = WorkflowJSONResourceError if resource else WorkflowJSONDomainError
    with pytest.raises(expected) as caught:
        bounded_json(value, **options)
    assert type(caught.value) is expected
    assert isinstance(caught.value, ValueError)


def test_unsupported_workflow_values_do_not_invoke_custom_representation():
    from review_boundary.workflow_cases import WorkflowJSONDomainError

    class Unsupported:
        def __repr__(self):
            raise AssertionError("The unsupported object must not be represented")

        def __str__(self):
            raise AssertionError("The unsupported object must not be converted")

    with pytest.raises(WorkflowJSONDomainError):
        bounded_json({"field": Unsupported()}, maximum=100)
