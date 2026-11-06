import json

import pytest

from review_boundary.budget import planned_cost, reserve


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
    assert reserve(ledger, 5, 20, "five")["total_reserved_usd"] == 20


def test_lock_fails_closed(tmp_path):
    ledger = tmp_path / "budget.json"
    ledger.with_suffix(".lock").touch()
    with pytest.raises(ValueError, match="locked"):
        reserve(ledger, 1, 20, "one")
    assert not ledger.exists()
