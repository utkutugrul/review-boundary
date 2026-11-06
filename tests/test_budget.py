import json

import pytest

from review_boundary.budget import planned_cost, reserve, settle


def test_reservation_bounds_known_cost():
    amount = planned_cost(48, 8, 24000, 1536, 0.15, 0.6)
    assert 3.2 < amount < 3.3
    assert planned_cost(96, 8, 24000, 1536, 0.15, 0.6) >= 2 * amount - 0.000001


@pytest.mark.parametrize("invalid", [0, -1, float("nan"), float("inf")])
def test_invalid_budget_input_is_rejected(invalid):
    with pytest.raises(ValueError):
        planned_cost(48, 8, 24000, 1536, invalid, 0.6)


def test_reservations_persist_across_runs_and_cannot_raise_limit(tmp_path):
    ledger = tmp_path / "budget.json"
    reserve(ledger, 7, 20, "one")
    reserve(ledger, 8, 20, "two")
    with pytest.raises(ValueError, match="Budget exceeded"):
        reserve(ledger, 6, 20, "three")
    with pytest.raises(ValueError, match="cannot be raised"):
        reserve(ledger, 6, 100, "four")
    assert len(json.loads(ledger.read_text())["runs"]) == 2
    assert reserve(ledger, 5, 20, "five")["total_accounted_usd"] == 20


def test_lock_fails_closed(tmp_path):
    ledger = tmp_path / "budget.json"
    ledger.with_suffix(".lock").touch()
    with pytest.raises(ValueError, match="locked"):
        reserve(ledger, 1, 20, "one")
    assert not ledger.exists()


def billing_report(tmp_path, **changes):
    report = tmp_path / "report.json"
    metadata = {
        "run_id": "one",
        "run_finished": True,
        "usage": {
            "provider_reported_cost_usd": 0.2,
            "api_calls_with_reported_cost": 12,
            "api_calls_without_reported_cost": 0,
        },
    }
    metadata.update(changes)
    report.write_text(json.dumps({"metadata": metadata}))
    return report


def test_settlement_retains_original_reserve_and_proof(tmp_path):
    ledger = tmp_path / "budget.json"
    reserve(ledger, 19, 20, "one")
    report = billing_report(tmp_path)
    proof = settle(ledger, "one", report)
    assert settle(ledger, "one", report) == proof
    data = json.loads(ledger.read_text())
    assert data["runs"][0]["reserved_usd"] == 19
    assert data["runs"][0]["settled_usd"] == 0.2
    assert reserve(ledger, 19, 20, "two")["total_accounted_usd"] == 19.2
    report.write_text(report.read_text() + "\n")
    with pytest.raises(ValueError, match="cannot be revised"):
        settle(ledger, "one", report)


@pytest.mark.parametrize(
    "changes",
    [
        {"run_finished": False},
        {"run_id": "wrong"},
        {
            "usage": {
                "provider_reported_cost_usd": 0,
                "api_calls_with_reported_cost": 0,
                "api_calls_without_reported_cost": 1,
            }
        },
        {
            "usage": {
                "provider_reported_cost_usd": float("nan"),
                "api_calls_with_reported_cost": 1,
                "api_calls_without_reported_cost": 0,
            }
        },
    ],
)
def test_unknown_or_invalid_billing_keeps_full_reservation(tmp_path, changes):
    ledger = tmp_path / "budget.json"
    reserve(ledger, 19, 20, "one")
    with pytest.raises(ValueError, match="Settlement requires"):
        settle(ledger, "one", billing_report(tmp_path, **changes))
    with pytest.raises(ValueError, match="Budget exceeded"):
        reserve(ledger, 2, 20, "two")


def test_provider_overrun_is_recorded_and_blocks_future_runs(tmp_path):
    ledger = tmp_path / "budget.json"
    reserve(ledger, 0.1, 20, "one")
    with pytest.raises(ValueError, match="exceeded the reservation"):
        settle(ledger, "one", billing_report(tmp_path))
    assert json.loads(ledger.read_text())["runs"][0]["settled_usd"] == 0.2
    with pytest.raises(ValueError, match="unresolved"):
        reserve(ledger, 1, 20, "two")
