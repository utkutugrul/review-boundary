"""Structural checks pin credential and artifact boundaries of reusable workflows."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    path = ROOT / ".github/workflows" / name
    return yaml.load(path.read_text(), Loader=yaml.BaseLoader)


def steps_using(job, action):
    return [step for step in job["steps"] if step.get("uses", "").startswith(action + "@")]


def test_adapter_workflow_accepts_no_secrets_and_uses_separate_ephemeral_read_only_jobs():
    value = workflow("evaluate-adapter.yml")
    assert "secrets" not in value["on"]["workflow_call"]
    assert "publish_comment" not in value["on"]["workflow_call"]["inputs"]
    assert value["permissions"] == {"contents": "read"}
    assert set(value["jobs"]) == {"adapter", "compare"}
    for job in value["jobs"].values():
        assert job["runs-on"] == "ubuntu-latest"
        assert job["permissions"] == {"contents": "read"}
        assert "environment" not in job and "secrets" not in job
        for step in job["steps"]:
            assert "secrets." not in str(step)
            assert "${{ inputs." not in step.get("run", "")
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
            if step.get("run", "").startswith("uv "):
                assert step["working-directory"] == "harness"
        for checkout in steps_using(job, "actions/checkout"):
            assert checkout["with"]["persist-credentials"] == "false"
        for setup in steps_using(job, "astral-sh/setup-uv"):
            assert setup["with"]["enable-cache"] == "false"
        assert not steps_using(job, "actions/cache")
        harness = [
            step
            for step in steps_using(job, "actions/checkout")
            if step["with"]["path"] == "harness"
        ]
        assert len(harness) == 1
        assert harness[0]["with"]["repository"] == "${{ job.workflow_repository }}"
        assert harness[0]["with"]["ref"] == "${{ job.workflow_sha }}"


def test_adapter_code_comes_from_head_while_both_jobs_reload_trusted_base_data():
    jobs = workflow("evaluate-adapter.yml")["jobs"]
    adapter = jobs["adapter"]
    caller = [
        step
        for step in steps_using(adapter, "actions/checkout")
        if step["with"]["path"] == "adapter-source"
    ]
    assert len(caller) == 1
    assert caller[0]["with"]["ref"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert caller[0]["with"]["repository"] == (
        "${{ github.event.pull_request.head.repo.full_name || github.repository }}"
    )
    check_index = next(
        index
        for index, step in enumerate(adapter["steps"])
        if step.get("run", "").endswith("actions adapter-check")
    )
    assert check_index < adapter["steps"].index(caller[0])
    for job in jobs.values():
        baseline = [
            step
            for step in steps_using(job, "actions/checkout")
            if step["with"]["path"] == "baseline-source"
        ]
        assert len(baseline) == 1
        assert (
            baseline[0]["with"]["ref"] == "${{ github.event.pull_request.base.sha || github.sha }}"
        )
        assert baseline[0]["if"] == "inputs.baseline_source == 'caller'"


def test_comparison_downloads_exact_artifact_and_never_executes_caller_adapter():
    jobs = workflow("evaluate-adapter.yml")["jobs"]
    adapter, compare = jobs["adapter"], jobs["compare"]
    assert adapter["outputs"]["artifact_id"] == "${{ steps.candidate.outputs.artifact-id }}"
    assert adapter["outputs"]["evaluation_exit"] == "${{ steps.run.outputs.evaluation_exit }}"
    candidate = steps_using(adapter, "actions/upload-artifact")
    assert len(candidate) == 1
    assert candidate[0]["with"]["path"] == "adapter-results/candidate/report.json"
    assert candidate[0]["with"]["if-no-files-found"] == "error"
    download = steps_using(compare, "actions/download-artifact")
    assert len(download) == 1
    assert download[0]["with"]["artifact-ids"] == "${{ needs.adapter.outputs.artifact_id }}"
    assert "name" not in download[0]["with"]
    assert "adapter-source" not in str(compare)
    assert "actions adapter-run" not in str(compare)
    comparison = next(step for step in compare["steps"] if step.get("id") == "run")
    assert comparison["env"]["RB_EVALUATION_EXIT"] == "${{ needs.adapter.outputs.evaluation_exit }}"
    assert comparison["run"].endswith("actions adapter-compare")
    assert comparison["working-directory"] == "harness"
    assert "PYTHONPATH" not in str(compare)
    assert "pip install" not in str(compare)
    assert "--project" not in str(compare)
    assert "steps.artifacts.outcome == 'success'" in compare["outputs"]["comparison_ready"]
    for job in jobs.values():
        assert job["steps"][-1]["if"] == "always()"
        assert "else 2" in job["steps"][-1]["run"]


def test_existing_provider_and_app_workflow_retains_trusted_code_and_immutable_artifacts():
    value = workflow("evaluate.yml")
    call = value["on"]["workflow_call"]
    assert call["inputs"]["publish_comment"]["default"] == "false"
    for job in value["jobs"].values():
        assert "actions adapter-run" not in str(job)
        assert "adapter-source" not in str(job)
        for checkout in steps_using(job, "actions/checkout"):
            assert checkout["with"]["persist-credentials"] == "false"
            if checkout["with"]["path"] == "harness":
                assert checkout["with"]["ref"] == "${{ job.workflow_sha }}"
    evaluate = value["jobs"]["evaluate"]
    check_index = next(
        index
        for index, step in enumerate(evaluate["steps"])
        if step.get("run") == "python3 harness/src/review_boundary/actions.py check"
    )
    provider_index = next(
        index
        for index, step in enumerate(evaluate["steps"])
        if "OPENAI_API_KEY" in step.get("env", {})
    )
    assert check_index < provider_index
    assert "RB_APP_PRIVATE_KEY" not in str(evaluate)
    report = value["jobs"]["report"]
    assert "github.event.pull_request.head.repo.full_name == github.repository" in report["if"]
    download = steps_using(report, "actions/download-artifact")[0]
    assert download["with"]["artifact-ids"] == "${{ needs.evaluate.outputs.artifact_id }}"
    assert "name" not in download["with"]


def test_repository_workflow_callers_never_forward_secrets_to_adapter_workflow():
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        value = workflow(path.name)
        for job in value.get("jobs", {}).values():
            if "evaluate-adapter.yml" in job.get("uses", ""):
                assert "secrets" not in job and "environment" not in job
