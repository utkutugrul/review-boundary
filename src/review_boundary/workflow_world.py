"""SDK-free workflow sessions with observed virtual effects and explicit bridges."""

import json
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .repository_cases import FrozenModel, utf8_size
from .repository_world import RepositoryLimitError, RepositoryLimits, RepositoryWorld
from .workflow_cases import (
    MAX_ARGUMENT_BYTES,
    MAX_BRIDGE_BYTES,
    REPOSITORY_TOOLS,
    WorkflowJSONDomainError,
    WorkflowJSONResourceError,
    WorkflowLimits,
    WorkflowRunBinding,
    bounded_json,
    byte_digest,
    canonical_bytes,
    checked,
    document_digest,
    validate_workflow_arguments,
    validate_workflow_case,
    workflow_case_digest,
    workflow_policy_document,
    workflow_tool_schemas,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
LIMIT_HEADROOM = 2048
LIMIT_RESPONSE_HEADROOM = 128
LimitReason = Literal["calls", "response_bytes", "trace_bytes", "argument_limit"]


def _unsupported_input_reason(result_json):
    for reason in ("non_object", "unsupported_workflow_value"):
        expected = {"status": "error", "error": "unsupported_arguments", "reason": reason}
        if result_json == canonical_bytes(expected).decode():
            return reason
    return None


class WorkflowEffect(FrozenModel):
    effect_id: Digest
    tool: Literal["save_report", "send_report"]
    target: str = Field(min_length=1, max_length=2048)
    content: str = Field(min_length=1, max_length=32768)
    intent_authorized: bool = Field(strict=True)
    sequence: int = Field(strict=True, ge=1, le=66)


class WorkflowEvent(FrozenModel):
    sequence: int = Field(strict=True, ge=1, le=66)
    tool: str = Field(min_length=1, max_length=64)
    arguments_json: str = Field(max_length=MAX_ARGUMENT_BYTES)
    argument_sha256: Digest | None
    arguments_omitted: bool = Field(strict=True, default=False)
    result_json: str = Field(max_length=16384)
    result_sha256: Digest
    status: Literal["ok", "error", "blocked", "limit"]
    capability_allowed: bool = Field(strict=True)
    intent_authorized: bool | None = Field(strict=True)
    disposition: Literal["data", "executed", "blocked", "invalid", "post_terminal", "limit"]
    effect_id: Digest | None = None
    limit_reason: LimitReason | None = None
    exposed: bool = Field(strict=True, default=False)

    @model_validator(mode="after")
    def coherent(self):
        args = self.arguments_json.encode()
        result = self.result_json.encode()
        if len(args) > MAX_ARGUMENT_BYTES or len(result) > 16384:
            raise ValueError("Workflow event byte limit")
        if not self.arguments_omitted and byte_digest(args) != self.argument_sha256:
            raise ValueError("Workflow argument digest mismatch")
        if byte_digest(result) != self.result_sha256:
            raise ValueError("Workflow result digest mismatch")
        rejection = _unsupported_input_reason(self.result_json)
        if self.arguments_omitted:
            if self.arguments_json != "{}":
                raise ValueError("An omitted workflow request requires the empty placeholder")
            if rejection is not None:
                if (
                    self.status != "error"
                    or self.disposition != "invalid"
                    or self.argument_sha256 is not None
                    or self.intent_authorized is not None
                    or self.effect_id is not None
                    or self.limit_reason is not None
                    or self.exposed
                ):
                    raise ValueError("Unsupported input requires a finite opaque error record")
            elif self.status != "limit":
                raise ValueError("Unsupported input requires a finite opaque error record")
        elif rejection is not None:
            raise ValueError("Unsupported input cannot claim recorded request bytes")
        if (self.status == "limit") != (self.limit_reason is not None):
            raise ValueError("Workflow limit metadata mismatch")
        if (self.disposition == "executed") != (self.effect_id is not None):
            raise ValueError("Workflow effect metadata mismatch")
        if self.disposition in ("executed", "blocked") and self.intent_authorized is None:
            raise ValueError("Resolved effect requires an authorization observation")
        return self


class WorkflowSnapshot(FrozenModel):
    schema_version: Literal[1] = 1
    snapshot_kind: Literal["workflow_session"] = "workflow_session"
    protocol: Literal["workflow-jsonl/1"] = "workflow-jsonl/1"
    scoring_version: Literal["workflow-scoring-v1"] = "workflow-scoring-v1"
    workflow_case_sha256: Digest
    session_index: int = Field(strict=True, ge=0, le=1)
    binding: WorkflowRunBinding
    actor: str = Field(min_length=1, max_length=64)
    guard: Literal["on", "off"]
    policy_sha256: Digest
    tools_sha256: Digest
    limits: WorkflowLimits
    repository_json: str = Field(max_length=1024 * 1024)
    events: tuple[WorkflowEvent, ...] = Field(max_length=66)
    effects: tuple[WorkflowEffect, ...] = Field(max_length=64)
    notes: tuple[str, ...] = Field(max_length=8)
    work_item_cursor: int = Field(strict=True, ge=0, le=2)
    calls: int = Field(strict=True, ge=0, le=65)
    output_bytes: int = Field(strict=True, ge=0, le=262144)
    tools_delivered: bool = Field(strict=True)
    carrier_exposed: bool = Field(strict=True)
    completed: bool = Field(strict=True)
    fatal_error: LimitReason | Literal["unsupported_arguments"] | None = None
    input_bridge_sha256: Digest | None = None
    producer_snapshot_sha256: Digest | None = None
    record_authority: Literal["recorded_data_only"] = "recorded_data_only"
    authenticity: Literal["not_established"] = "not_established"

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int:
            raise ValueError("Workflow snapshot version requires an exact integer")
        return value

    @model_validator(mode="after")
    def coherent(self):
        if [event.sequence for event in self.events] != list(range(1, len(self.events) + 1)):
            raise ValueError("Workflow event sequence mismatch")
        delivery = [e for e in self.events if e.tool == "tool_delivery"]
        if len(delivery) != int(self.tools_delivered) or delivery and delivery[0].sequence != 1:
            raise ValueError("Workflow tool delivery mismatch")
        if self.calls != len(self.events) - len(delivery):
            raise ValueError("Workflow call count mismatch")
        response_bytes = sum(
            len(event.result_json.encode("utf-8"))
            for event in self.events
            if event.tool != "tool_delivery"
        )
        if (
            self.output_bytes != response_bytes
            or response_bytes > self.limits.max_total_response_bytes
        ):
            raise ValueError("Workflow response byte count mismatch")
        if self.calls > self.limits.max_calls + int(self.fatal_error == "calls"):
            raise ValueError("Workflow call limit mismatch")
        if any(e.arguments_omitted for e in self.events[:-1]):
            raise ValueError("Only the final refused input may be omitted")
        if self.fatal_error == "unsupported_arguments":
            if (
                not self.events
                or not self.events[-1].arguments_omitted
                or self.events[-1].status != "error"
                or _unsupported_input_reason(self.events[-1].result_json) is None
                or self.completed
            ):
                raise ValueError("Workflow unsupported-input fatal state mismatch")
        elif self.fatal_error and (
            not self.events or self.events[-1].limit_reason != self.fatal_error
        ):
            raise ValueError("Workflow fatal state mismatch")
        for note in self.notes:
            utf8_size(note, 2048)
        if (
            len(canonical_bytes(list(self.notes), maximum=MAX_BRIDGE_BYTES, nodes=4096))
            > MAX_BRIDGE_BYTES
        ):
            raise ValueError("Workflow note budget")
        canonical_bytes(self, maximum=self.limits.max_trace_bytes)
        return self


class WorkflowBridge(FrozenModel):
    schema_version: Literal[1] = 1
    bridge_kind: Literal["memory", "handoff"]
    workflow_case_sha256: Digest
    binding: WorkflowRunBinding
    guard: Literal["on", "off"]
    producer_session: Literal[0] = 0
    consumer_session: Literal[1] = 1
    producer_snapshot_sha256: Digest
    entries: tuple[str, ...] = Field(min_length=1, max_length=8)
    payload_sha256: Digest
    payload_byte_count: int = Field(strict=True, ge=1, le=MAX_BRIDGE_BYTES)
    record_authority: Literal["recorded_data_only"] = "recorded_data_only"
    authorization: Literal["untrusted_data_only"] = "untrusted_data_only"

    @field_validator("schema_version", "producer_session", "consumer_session", mode="before")
    @classmethod
    def exact_versions(cls, value):
        if type(value) is not int:
            raise ValueError("Workflow bridge identities require exact integers")
        return value

    @model_validator(mode="after")
    def coherent(self):
        for entry in self.entries:
            utf8_size(entry, 2048)
        raw = canonical_bytes(list(self.entries), maximum=MAX_BRIDGE_BYTES, nodes=4096)
        if byte_digest(raw) != self.payload_sha256 or len(raw) != self.payload_byte_count:
            raise ValueError("Workflow bridge payload mismatch")
        canonical_bytes(self, maximum=MAX_BRIDGE_BYTES, nodes=4096, depth=16)
        return self


class WorkflowSessionWorld:
    """One fresh repository view; only checked bridge entries can cross sessions."""

    def __init__(
        self,
        case,
        session_index,
        guard="on",
        *,
        binding,
        bridge=None,
        producer_snapshot=None,
        limits=None,
    ):
        self.case = validate_workflow_case(case)
        if type(session_index) is not int or not 0 <= session_index < len(self.case.sessions):
            raise ValueError("Unknown workflow session")
        if guard not in ("on", "off"):
            raise ValueError("Unknown workflow guard")
        self.session_index, self.guard = session_index, guard
        self.binding = checked(WorkflowRunBinding, binding)
        self.limits = checked(WorkflowLimits, limits or WorkflowLimits())
        self.session = self.case.sessions[session_index]
        self._repo_limits = RepositoryLimits(
            max_calls=self.limits.max_calls,
            max_response_bytes=self.limits.max_response_bytes,
            max_total_response_bytes=self.limits.max_total_response_bytes,
        )
        self._repository = RepositoryWorld(self.case.repository, self._repo_limits)
        self._events = ()
        self._effects = ()
        self._notes = ()
        self._cursor = 0
        self._calls = self._output_bytes = 0
        self._delivered = self._exposed = self._completed = False
        self._fatal = None
        self._bridge = None
        self._bridge_sha = self._producer_sha = None
        if session_index == 0:
            if bridge is not None or producer_snapshot is not None:
                raise ValueError("First session cannot inherit another conversation")
        else:
            if bridge is None or producer_snapshot is None:
                raise ValueError("Consumer requires explicit bridge bytes and producer evidence")
            self._bridge = restore_workflow_bridge(
                self.case,
                session_index,
                bridge,
                binding=self.binding,
                guard=guard,
                producer_snapshot=producer_snapshot,
                limits=self.limits,
            )
            self._bridge_sha = byte_digest(bridge)
            self._producer_sha = self._bridge.producer_snapshot_sha256

    def _snapshot_data(
        self,
        *,
        repository=None,
        events=None,
        effects=None,
        notes=None,
        cursor=None,
        calls=None,
        output_bytes=None,
        exposed=None,
        completed=None,
        delivered=None,
        fatal=None,
    ):
        return {
            "schema_version": 1,
            "snapshot_kind": "workflow_session",
            "protocol": "workflow-jsonl/1",
            "scoring_version": "workflow-scoring-v1",
            "workflow_case_sha256": workflow_case_digest(self.case),
            "session_index": self.session_index,
            "binding": self.binding.model_dump(mode="json"),
            "actor": self.session.actor,
            "guard": self.guard,
            "policy_sha256": document_digest(
                workflow_policy_document(self.case, self.session_index)
            ),
            "tools_sha256": document_digest(workflow_tool_schemas(self.case, self.session_index)),
            "limits": self.limits.model_dump(mode="json"),
            "repository_json": canonical_bytes(
                (repository or self._repository).snapshot()
            ).decode(),
            "events": [
                e.model_dump(mode="json") for e in (self._events if events is None else events)
            ],
            "effects": [
                e.model_dump(mode="json") for e in (self._effects if effects is None else effects)
            ],
            "notes": list(self._notes if notes is None else notes),
            "work_item_cursor": self._cursor if cursor is None else cursor,
            "calls": self._calls if calls is None else calls,
            "output_bytes": self._output_bytes if output_bytes is None else output_bytes,
            "tools_delivered": self._delivered if delivered is None else delivered,
            "carrier_exposed": self._exposed if exposed is None else exposed,
            "completed": self._completed if completed is None else completed,
            "fatal_error": self._fatal if fatal is None else fatal,
            "input_bridge_sha256": self._bridge_sha,
            "producer_snapshot_sha256": self._producer_sha,
            "record_authority": "recorded_data_only",
            "authenticity": "not_established",
        }

    def snapshot(self):
        return checked(WorkflowSnapshot, self._snapshot_data()).model_dump(mode="json")

    @property
    def completed(self):
        return self._completed

    @property
    def fatal_error(self):
        return self._fatal

    def record_tool_delivery(self, schemas):
        if self._events or self._delivered:
            raise ValueError("Tool delivery is a one-use pre-call observation")
        actual = bounded_json(schemas, maximum=128 * 1024, nodes=65536)
        expected = workflow_tool_schemas(self.case, self.session_index)
        if actual != canonical_bytes(expected):
            raise ValueError("Delivered workflow tools do not match the case/session")
        result = {"status": "ok", "tools_sha256": byte_digest(actual)}
        event = self._event(
            "tool_delivery",
            {},
            result,
            capability=False,
            exposed=self.session.exposure == "tool_description",
        )
        candidate = self._snapshot_data(events=(event,), delivered=True, exposed=event.exposed)
        if len(canonical_bytes(candidate)) + LIMIT_HEADROOM > self.limits.max_trace_bytes:
            raise ValueError("Initial tool observation exceeds trace budget")
        self._events, self._delivered = (event,), True
        self._exposed = event.exposed

    def _event(
        self,
        name,
        arguments,
        result,
        *,
        capability,
        authorization=None,
        disposition="data",
        effect_id=None,
        exposed=False,
        limit_reason=None,
        omitted=False,
        argument_sha=None,
    ):
        args = canonical_bytes(arguments, maximum=MAX_ARGUMENT_BYTES)
        raw = canonical_bytes(result, maximum=16384)
        return WorkflowEvent(
            sequence=len(self._events) + 1,
            tool=name,
            arguments_json=args.decode(),
            argument_sha256=argument_sha if omitted else byte_digest(args),
            arguments_omitted=omitted,
            result_json=raw.decode(),
            result_sha256=byte_digest(raw),
            status=result["status"],
            capability_allowed=capability,
            intent_authorized=authorization,
            disposition=disposition,
            effect_id=effect_id,
            exposed=exposed,
            limit_reason=limit_reason,
        )

    def _record_limit(self, reason, name="unknown", argument_sha=None):
        if self._fatal:
            raise ValueError("Workflow session is already limited")
        safe_name = name if type(name) is str and 0 < len(name) <= 64 else "unknown"
        if safe_name == "tool_delivery":
            safe_name = "unknown"
        result = {"status": "limit", "error": reason}
        event = self._event(
            safe_name,
            {},
            result,
            capability=safe_name in self.session.tools,
            disposition="limit",
            limit_reason=reason,
            omitted=True,
            argument_sha=argument_sha,
        )
        data = self._snapshot_data(
            events=(*self._events, event),
            calls=self._calls + 1,
            output_bytes=self._output_bytes + len(event.result_json.encode("utf-8")),
            completed=False,
            fatal=reason,
        )
        canonical_bytes(data, maximum=self.limits.max_trace_bytes)
        checked(WorkflowSnapshot, data)
        self._events = (*self._events, event)
        self._calls += 1
        self._output_bytes = data["output_bytes"]
        self._completed, self._fatal = False, reason
        return result

    def _record_input_rejection(self, reason, name="unknown"):
        if self._fatal:
            raise ValueError("Workflow session is already terminal")
        if type(reason) is not str or reason not in ("non_object", "unsupported_workflow_value"):
            raise ValueError("Unknown unsupported-input reason")
        safe_name = name if type(name) is str and 0 < len(name) <= 64 else "unknown"
        if safe_name == "tool_delivery":
            safe_name = "unknown"
        result = {"status": "error", "error": "unsupported_arguments", "reason": reason}
        event = self._event(
            safe_name,
            {},
            result,
            capability=safe_name in self.session.tools,
            disposition="invalid",
            omitted=True,
        )
        data = self._snapshot_data(
            events=(*self._events, event),
            calls=self._calls + 1,
            output_bytes=self._output_bytes + len(event.result_json.encode("utf-8")),
            completed=False,
            fatal="unsupported_arguments",
        )
        canonical_bytes(data, maximum=self.limits.max_trace_bytes)
        checked(WorkflowSnapshot, data)
        self._events = (*self._events, event)
        self._calls += 1
        self._output_bytes = data["output_bytes"]
        self._completed, self._fatal = False, "unsupported_arguments"
        return result

    def _post_item_source_observed(self):
        first_item_delivered = False
        for event in self._events:
            if event.status != "ok" or event.tool not in (
                "read_work_item",
                "read_file",
                "search_files",
            ):
                continue
            result = json.loads(event.result_json)
            if event.tool == "read_work_item" and "text" in result:
                first_item_delivered = True
            elif first_item_delivered and (
                (event.tool == "read_file" and result.get("lines"))
                or (event.tool == "search_files" and result.get("matches"))
            ):
                return True
        return False

    def dispatch(self, name, arguments):
        if self._fatal == "unsupported_arguments":
            raise ValueError("Workflow session rejected unsupported arguments")
        if self._fatal:
            raise ValueError("Workflow session is already limited")
        if not self._delivered:
            raise ValueError("Record actual tool delivery before workflow calls")
        safe_name = name if type(name) is str and 0 < len(name) <= 64 else "unknown"
        if safe_name == "tool_delivery":
            safe_name = "unknown"
        if self._calls >= self.limits.max_calls:
            return self._record_limit("calls", safe_name)
        if type(arguments) is not dict:
            return self._record_input_rejection("non_object", safe_name)
        try:
            arg_raw = bounded_json(arguments, maximum=MAX_ARGUMENT_BYTES, nodes=4096)
        except WorkflowJSONResourceError:
            return self._record_limit("argument_limit", safe_name)
        except WorkflowJSONDomainError:
            return self._record_input_rejection("unsupported_workflow_value", safe_name)
        try:
            args = validate_workflow_arguments(safe_name, arguments)
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            args = None
        repository = RepositoryWorld.from_snapshot(
            self.case.repository,
            self._repository.snapshot(),
            expected_limits=self._repo_limits,
        )
        notes, effects, cursor = self._notes, self._effects, self._cursor
        exposed, complete = self._exposed, self._completed
        capability = safe_name in self.session.tools
        authorization, effect_id = None, None
        disposition = "data"
        if args is None or not capability:
            result, disposition = {"status": "error", "error": "invalid_arguments"}, "invalid"
        elif complete:
            result, disposition = {"status": "error", "error": "already_submitted"}, "post_terminal"
        elif safe_name in REPOSITORY_TOOLS:
            try:
                result = repository.dispatch(safe_name, args)
            except RepositoryLimitError:
                return self._record_limit("response_bytes", safe_name, byte_digest(arg_raw))
            complete = safe_name == "submit_review" and result["status"] == "ok"
        elif safe_name == "read_work_item":
            if (
                cursor == 1
                and len(self.session.work_items) == 2
                and not self._post_item_source_observed()
            ):
                result = {"status": "error", "error": "inspection_required"}
            elif cursor >= len(self.session.work_items):
                result = {"status": "ok", "exhausted": True}
            else:
                result = {"status": "ok", "text": self.session.work_items[cursor]}
                exposed = (
                    exposed
                    or self.session.exposure == "work_item"
                    or (self.session.exposure == "late_work_item" and cursor == 1)
                )
                cursor += 1
        elif safe_name in ("remember_note", "write_handoff"):
            if len(notes) >= 8:
                result = {"status": "error", "error": "note_limit"}
            else:
                proposed = (*notes, args["text"])
                try:
                    canonical_bytes(list(proposed), maximum=MAX_BRIDGE_BYTES - 2048, nodes=4096)
                except WorkflowJSONResourceError:
                    result = {"status": "error", "error": "note_limit"}
                else:
                    notes = proposed
                    result = {
                        "status": "ok",
                        "stored": len(notes),
                        "authority": "untrusted_data_only",
                    }
        elif safe_name in ("recall_notes", "read_handoff"):
            if self._bridge is None:
                result = {"status": "error", "error": "bridge_not_supplied"}
            else:
                result = {
                    "status": "ok",
                    "entries": list(self._bridge.entries),
                    "authority": "untrusted_data_only",
                }
                exposed = (
                    exposed
                    or self.case.payload_marker is None
                    or any(self.case.payload_marker in entry for entry in self._bridge.entries)
                )
        else:
            target = args["path" if safe_name == "save_report" else "url"]
            try:
                utf8_size(target, 2048)
                utf8_size(args["content"], 32768)
                if not target.strip():
                    raise ValueError("Empty workflow target")
            except ValueError:
                result, disposition = {"status": "error", "error": "invalid_arguments"}, "invalid"
            else:
                authorization = any(
                    (g.tool, g.target, g.purpose) == (safe_name, target, self.session.purpose)
                    for g in self.session.grants
                )
                if self.guard == "on" and not authorization:
                    result, disposition = (
                        {"status": "blocked", "reason": "outside_trusted_intent"},
                        "blocked",
                    )
                else:
                    value = {
                        "tool": safe_name,
                        "target": target,
                        "content": args["content"],
                        "intent_authorized": authorization,
                        "sequence": len(self._events) + 1,
                    }
                    effect_id = document_digest(value)
                    effects = (*effects, WorkflowEffect(effect_id=effect_id, **value))
                    result, disposition = {"status": "ok", "effect_id": effect_id}, "executed"
        try:
            result_raw = canonical_bytes(result, maximum=self.limits.max_response_bytes)
        except WorkflowJSONResourceError:
            return self._record_limit("response_bytes", safe_name, byte_digest(arg_raw))
        output = self._output_bytes + len(result_raw)
        if output + LIMIT_RESPONSE_HEADROOM > self.limits.max_total_response_bytes:
            return self._record_limit("response_bytes", safe_name, byte_digest(arg_raw))
        event = self._event(
            safe_name,
            json.loads(arg_raw),
            result,
            capability=capability,
            authorization=authorization,
            disposition=disposition,
            effect_id=effect_id,
            exposed=exposed and not self._exposed,
        )
        candidate = self._snapshot_data(
            repository=repository,
            events=(*self._events, event),
            effects=effects,
            notes=notes,
            cursor=cursor,
            calls=self._calls + 1,
            output_bytes=output,
            exposed=exposed,
            completed=complete,
        )
        try:
            fits = len(canonical_bytes(candidate)) + LIMIT_HEADROOM <= self.limits.max_trace_bytes
        except WorkflowJSONResourceError:
            fits = False
        if not fits:
            return self._record_limit("trace_bytes", safe_name, byte_digest(arg_raw))
        checked(WorkflowSnapshot, candidate)
        self._repository, self._notes, self._effects = repository, notes, effects
        self._events = (*self._events, event)
        self._cursor, self._calls, self._output_bytes = cursor, self._calls + 1, output
        self._exposed, self._completed = exposed, complete
        return json.loads(result_raw)


def seal_workflow_bridge(case, producer_snapshot, *, binding, guard, limits=None):
    """Seal only actual replayed producer writes, never a claimed completion flag."""
    from .workflow_replay import replay_workflow

    case = validate_workflow_case(case)
    if case.bridge_kind is None:
        raise ValueError("This workflow has no bridge")
    verified = replay_workflow(
        case,
        (producer_snapshot,),
        expected_guard=guard,
        expected_binding=binding,
        expected_limits=limits or WorkflowLimits(),
    )
    source = verified.snapshots[0]
    if not source.completed or source.fatal_error or not source.notes:
        raise ValueError("Bridge producer is incomplete or has no observed writes")
    if source.events[-1].tool != "submit_review" or source.events[-1].status != "ok":
        raise ValueError("Bridge producer is not terminal")
    payload = canonical_bytes(list(source.notes), maximum=MAX_BRIDGE_BYTES, nodes=4096)
    bridge = WorkflowBridge(
        bridge_kind=case.bridge_kind,
        workflow_case_sha256=workflow_case_digest(case),
        binding=checked(WorkflowRunBinding, binding),
        guard=guard,
        producer_snapshot_sha256=document_digest(source),
        entries=source.notes,
        payload_sha256=byte_digest(payload),
        payload_byte_count=len(payload),
    )
    return canonical_bytes(bridge, maximum=MAX_BRIDGE_BYTES, nodes=4096, depth=16)


def restore_workflow_bridge(
    case, consumer_index, raw, *, binding, guard, producer_snapshot, limits=None
):
    if type(raw) is not bytes or type(consumer_index) is not int or consumer_index != 1:
        raise ValueError("Bridge requires explicit bytes and its consumer session")
    value = checked(WorkflowBridge, raw, maximum=MAX_BRIDGE_BYTES, nodes=4096, depth=16, wire=True)
    expected = seal_workflow_bridge(
        case,
        producer_snapshot,
        binding=binding,
        guard=guard,
        limits=limits or WorkflowLimits(),
    )
    if raw != expected or value.consumer_session != consumer_index:
        raise ValueError("Workflow bridge does not bind the actual producer and consumer")
    return value
