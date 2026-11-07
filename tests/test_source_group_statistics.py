"""Numerical tests for review_boundary.source_group_analysis.

The frozen protocol fixes the aggregation weights (pooled epochs within a
case/run, then equal weight for runs, cases and sources), the SHA-256 wire
format of the roster, draw and result digests, and the rejection-sampled
source draw. Expected values here are hand computed Fractions or fixed vectors
generated once outside the production code from the frozen wire algorithm,
using only the standard library. The six-source interval for seed 0 and 100
resamples is pinned as a finite vector; the exact binomial multiset is the
independent oracle for the inverse-CDF endpoints.
"""

import hashlib
import json
import math
from fractions import Fraction as F

import pytest

from review_boundary import source_group_analysis as sga
from review_boundary.source_group_analysis import (
    MetricContribution,
    aggregate_metric,
    source_sensitivity,
)

KEYS = ("source-a", "source-b", "source-c", "source-d", "source-e", "source-f")
VALUES = (F(0), F(0), F(0), F(1), F(1), F(1))
CELL = "independent-six-source"
EMPTY_ROSTER_SHA = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
VECTOR_ORDERED_SHA = "48e279c814bfbb4a5d8695866a161634468157a6b3631ce11b5fa30986a66c9b"
VECTOR_DRAW_SHA = "7c8f57b103ce3e53a3817d6ea1886579fe9876a384156980c1a1ff9abaf28a63"
VECTOR_RESULT_SHA = "72046142f5ebb9bf8d5cba06e0ce9adce151a31447871b3421f2aae57cbd5fee"
FIXED_DRAWS = {
    0: [0, 0, 4, 5, 2, 2],
    1: [3, 1, 0, 2, 3, 0],
    2: [5, 3, 5, 1, 1, 2],
    3: [1, 4, 2, 3, 4, 2],
    4: [0, 3, 2, 2, 4, 1],
    49: [4, 0, 2, 3, 3, 1],
    99: [4, 4, 1, 4, 1, 3],
}
# Rejection limit for six groups: floor(2**64 / 6) * 6.
LIMIT = 2**64 - 4
BASE_DRAW = {"seed": 0, "cell_key": CELL, "replicate": 0, "draw": 0, "groups": 6}


def C(source, case, run, num, den):
    return MetricContribution(
        source_key=source, case_key=case, run_key=run, numerator=num, denominator=den
    )


def pairs():
    return tuple(zip(KEYS, VALUES))


def sens(source_values, **kw):
    kw.setdefault("cell_key", CELL)
    kw.setdefault("resamples", 100)
    return source_sensitivity(tuple(source_values), **kw)


def wire_digest(payload):
    text = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------- aggregate_metric ----------


def example_b():
    # run1: one epoch [1,0,1]; run2: three epochs, A1=[0,0,0], A2 missing, B1=[1,1,1]
    return (
        C("A", "A1", "run1", 1, 1),
        C("A", "A2", "run1", 0, 1),
        C("B", "B1", "run1", 1, 1),
        C("A", "A1", "run2", 0, 3),
        C("A", "A2", "run2", 0, 0),
        C("B", "B1", "run2", 3, 3),
    )


def test_hand_example_b_pooled_versus_equal_weight_estimate():
    r = aggregate_metric(example_b())
    assert r.pooled == F(5, 9)
    assert r.estimate == F(5, 8)
    assert (r.numerator, r.denominator) == (5, 9)
    assert r.case_run_values == (
        ("A", "A1", "run1", F(1)),
        ("A", "A1", "run2", F(0)),
        ("A", "A2", "run1", F(0)),
        ("A", "A2", "run2", None),
        ("B", "B1", "run1", F(1)),
        ("B", "B1", "run2", F(1)),
    )
    assert r.case_values == (
        ("A", "A1", F(1, 2)),
        ("A", "A2", F(0)),
        ("B", "B1", F(1)),
    )
    assert r.source_values == (("A", F(1, 4)), ("B", F(1)))


def test_cases_weigh_equally_regardless_of_epoch_count():
    r = aggregate_metric((C("S", "c1", "r", 1, 1), C("S", "c2", "r", 0, 50)))
    assert r.case_values == (("S", "c1", F(1)), ("S", "c2", F(0)))
    assert r.estimate == F(1, 2)
    assert r.pooled == F(1, 51)


def test_runs_weigh_equally_regardless_of_epoch_count():
    r = aggregate_metric((C("S", "c", "r1", 1, 1), C("S", "c", "r2", 0, 9)))
    assert r.estimate == F(1, 2)
    assert r.pooled == F(1, 10)


def test_unequal_sources_get_equal_weight():
    rows = [C("big", f"c{i}", "r", 1, 2) for i in range(5)]
    rows.append(C("small", "c", "r", 1, 1))
    r = aggregate_metric(tuple(rows))
    assert r.source_values == (("big", F(1, 2)), ("small", F(1)))
    assert r.estimate == F(3, 4)


def test_null_only_group_is_not_zero_and_not_contributing():
    rows = (C("A", "c", "r", 1, 2), C("Z", "c", "r", 0, 0), C("Z", "d", "r", 0, 0))
    r = aggregate_metric(rows)
    assert r.source_values == (("A", F(1, 2)), ("Z", None))
    assert r.case_values[-2:] == (("Z", "c", None), ("Z", "d", None))
    assert r.estimate == F(1, 2)  # a zero fill for Z would give 1/4
    assert (r.numerator, r.denominator) == (1, 2)


def test_empty_and_fully_null_input_have_no_estimate():
    assert aggregate_metric(()).estimate is None
    r = aggregate_metric((C("Z", "c", "r", 0, 0),))
    assert r.estimate is None and r.pooled is None
    assert r.source_values == (("Z", None),)


def test_input_permutation_gives_identical_output():
    rows = example_b()
    assert aggregate_metric(rows[::-1]) == aggregate_metric(rows)


def test_signed_paired_deltas():
    rows = (
        C("A", "c", "r1", -1, 2),
        C("A", "c", "r2", 1, 2),
        C("B", "c", "r1", 1, 2),
    )
    r = aggregate_metric(rows)
    assert r.source_values == (("A", F(0)), ("B", F(1, 2)))
    assert r.estimate == F(1, 4)
    assert r.pooled == F(1, 6)
    single = aggregate_metric((C("A", "c", "r1", 1, 1), C("A", "c", "r2", -1, 1)))
    assert single.estimate == F(0)
    assert single.source_values == (("A", F(0)),)


def test_duplicate_source_case_run_rejected():
    with pytest.raises(ValueError):
        aggregate_metric((C("A", "c", "r", 1, 1), C("A", "c", "r", 0, 1)))
    with pytest.raises(ValueError):
        aggregate_metric((C("A", "c", "r", 1, 1), C("A", "c", "r", 1, 1)))


@pytest.mark.parametrize(
    "num,den",
    [
        (True, 1),
        (1, True),
        (1.0, 1),
        (1, 1.0),
        (F(1), 1),
        ("1", 1),
        (1, -1),
        (1, 0),
        (-1, 0),
    ],
)
def test_contribution_strict_numeric_guards(num, den):
    with pytest.raises(ValueError):
        C("A", "c", "r", num, den)


@pytest.mark.parametrize(
    "src,case,run",
    [("", "c", "r"), ("A", "", "r"), ("A", "c", ""), (1, "c", "r")],
)
def test_contribution_rejects_bad_keys(src, case, run):
    with pytest.raises(ValueError):
        C(src, case, run, 0, 1)


# ---------- _inverse_cdf ----------


def test_exact_binomial_multiplicities_prove_inverse_cdf_interval():
    # Oracle: the 2**6 equally likely binary outcome patterns compress the 6**6 source-index
    # sequences, each pattern standing for equally many. Pattern means are k/6 with
    # multiplicity C(6, k), the Binomial(6, 1/2) counts; the order is deliberately reversed.
    population = [F(k, 6) for k in range(7) for _ in range(math.comb(6, k))]
    population.reverse()
    assert len(population) == 64
    assert sga._inverse_cdf(tuple(population), 25, 1000) == F(1, 6)
    assert sga._inverse_cdf(tuple(population), 975, 1000) == F(5, 6)


def test_b120_exact_integer_endpoint_quantiles():
    # ceil(0.025 * 120) - 1 == 2 and ceil(0.975 * 120) - 1 == 116.
    vals = tuple(F(i) for i in reversed(range(120)))
    assert sga._inverse_cdf(vals, 25, 1000) == F(2)
    assert sga._inverse_cdf(vals, 975, 1000) == F(116)
    assert sga._inverse_cdf(vals, 0, 1000) == F(0)  # p0 clamps to the minimum
    assert sga._inverse_cdf(vals, 1, 1) == F(119)  # p1 is the maximum
    assert sga._inverse_cdf(vals, 1, 2) == F(59)


@pytest.mark.parametrize(
    "values,num,den",
    [
        ((), 1, 2),
        ((0.5,), 1, 2),
        ((F(1),), True, 2),
        ((F(1),), 1, True),
        ((F(1),), 1, 0),
        ((F(1),), 3, 2),
        ((F(1),), -1, 2),
        ((F(1),), 1.0, 2),
        (tuple(F(i) for i in range(10001)), 1, 2),
    ],
)
def test_inverse_cdf_rejects_invalid_inputs(values, num, den):
    with pytest.raises(ValueError):
        sga._inverse_cdf(values, num, den)


# ---------- _source_draw_index ----------


@pytest.mark.parametrize("replicate,expected", sorted(FIXED_DRAWS.items()))
def test_draw_index_matches_independent_vectors(replicate, expected):
    got = [
        sga._source_draw_index(**{**BASE_DRAW, "replicate": replicate, "draw": d}) for d in range(6)
    ]
    assert got == expected


def _patch_digest(monkeypatch, outputs):
    calls = []
    queue = list(outputs)

    def fake(payload):
        calls.append(list(payload))
        return f"{queue.pop(0):016x}" + "0" * 48

    monkeypatch.setattr(sga, "json_digest", fake)
    return calls


def test_x_equal_limit_rejected_then_retry_index_uses_accepted_draw(monkeypatch):
    calls = _patch_digest(monkeypatch, [LIMIT, 7])
    got = sga._source_draw_index(seed=3, cell_key="cell", replicate=2, draw=4, groups=6)
    assert got == 1  # accepting x=LIMIT would have returned 0
    assert calls == [
        ["rb-source-bootstrap-v1", 3, "cell", 2, 4, 0],
        ["rb-source-bootstrap-v1", 3, "cell", 2, 4, 1],
    ]


def test_multiple_rejections_increment_retry_each_time(monkeypatch):
    calls = _patch_digest(monkeypatch, [LIMIT, 2**64 - 1, 13])
    assert sga._source_draw_index(**{**BASE_DRAW, "cell_key": "k"}) == 1
    assert [c[-1] for c in calls] == [0, 1, 2]


def test_x_just_below_limit_is_accepted_without_retry(monkeypatch):
    calls = _patch_digest(monkeypatch, [LIMIT - 1])
    assert sga._source_draw_index(**{**BASE_DRAW, "cell_key": "k"}) == 5
    assert len(calls) == 1


def test_digest_uses_first_eight_bytes_big_endian(monkeypatch):
    fake_hex = "0000000000000102" + "ff" * 24
    monkeypatch.setattr(sga, "json_digest", lambda payload: fake_hex)
    assert sga._source_draw_index(**{**BASE_DRAW, "groups": 256}) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("seed", True),
        ("seed", -1),
        ("seed", 2**63),
        ("seed", 1.0),
        ("groups", 0),
        ("groups", 257),
        ("groups", True),
        ("replicate", -1),
        ("replicate", 10000),
        ("replicate", False),
        ("draw", -1),
        ("draw", 6),
        ("draw", True),
    ],
)
def test_draw_index_rejects_invalid_bounds_and_types(field, value):
    with pytest.raises(ValueError):
        sga._source_draw_index(**{**BASE_DRAW, field: value})


def test_draw_index_accepts_boundary_values():
    top = sga._source_draw_index(seed=2**63 - 1, cell_key="k", replicate=9999, draw=255, groups=256)
    assert 0 <= top < 256
    assert sga._source_draw_index(**{**BASE_DRAW, "groups": 1}) == 0


# ---------- source_sensitivity ----------


def test_g0_has_no_estimate_interval_or_draws():
    r = sens(())
    assert r.groups == 0 and r.status == "no_sources"
    assert r.estimate is None and r.interval is None
    assert r.draw_sha256 is None and r.result_sha256 is None
    assert r.ordered_cluster_sha256 == EMPTY_ROSTER_SHA == wire_digest([])


def test_g1_single_source_has_point_only():
    r = sens((("only", F(1, 3)),))
    assert (r.groups, r.status, r.estimate) == (1, "single_source", F(1, 3))
    assert r.interval is None and r.draw_sha256 is None and r.result_sha256 is None
    assert r.ordered_cluster_sha256 == wire_digest(["only"])


@pytest.mark.parametrize("g", [2, 3, 4, 5])
def test_g2_to_g5_report_range_and_leave_one_out_without_interval(g):
    vals = [F(i * i, 3) for i in range(g)]
    total = sum(vals)
    loo = [(total - v) / (g - 1) for v in vals]
    r = sens(tuple((f"s{i}", v) for i, v in enumerate(vals)))
    assert (r.groups, r.status) == (g, "few_sources")
    assert r.estimate == total / g
    assert r.source_range == (min(vals), max(vals))
    assert r.leave_one_out_range == (min(loo), max(loo))
    assert r.interval is None and r.draw_sha256 is None and r.result_sha256 is None


def test_g6_fixed_vector_pins_digests_and_finite_interval():
    r = sens(pairs())
    assert (r.groups, r.status, r.estimate) == (6, "descriptive", F(1, 2))
    assert (r.seed, r.resamples) == (0, 100)
    assert r.ordered_cluster_sha256 == VECTOR_ORDERED_SHA == wire_digest(list(KEYS))
    assert r.draw_sha256 == VECTOR_DRAW_SHA
    assert r.result_sha256 == VECTOR_RESULT_SHA
    # Finite vector for this seed; it coincides with the exact binomial interval.
    assert r.interval == (F(1, 6), F(5, 6))


def test_permutation_does_not_change_statistics_or_digests():
    assert sens(pairs()[::-1]) == sens(pairs())


def test_null_sources_are_excluded_from_g_and_digests():
    with_null = sens(pairs() + (("source-z", None),))
    base = sens(pairs())
    assert with_null.groups == 6
    assert with_null.ordered_cluster_sha256 == base.ordered_cluster_sha256
    assert with_null.draw_sha256 == base.draw_sha256
    assert with_null.interval == base.interval
    five = sens(pairs()[:5] + (("source-f", None),))
    assert five.groups == 5 and five.status == "few_sources" and five.interval is None
    assert five.ordered_cluster_sha256 == wire_digest(list(KEYS[:5]))


def test_all_null_sources_behave_like_g0_but_keep_empty_roster_hash():
    r = sens((("a", None), ("b", None)))
    assert r.groups == 0 and r.estimate is None and r.interval is None
    assert r.ordered_cluster_sha256 == EMPTY_ROSTER_SHA


def test_constant_source_values_are_degenerate():
    r = sens(tuple((k, F(1, 2)) for k in KEYS))
    assert r.groups == 6 and r.status == "degenerate"
    assert r.estimate == F(1, 2) and r.interval == (F(1, 2), F(1, 2))
    zeros = sens(tuple((k, F(0)) for k in KEYS))
    assert zeros.status == "degenerate" and zeros.interval == (F(0), F(0))


def test_paired_delta_pipeline_from_contributions_to_interval():
    rows = tuple(C(k, "case", "run", int(v), 1) for k, v in pairs())
    agg = aggregate_metric(rows)
    assert agg.estimate == F(1, 2)
    r = sens(agg.source_values)
    assert r.result_sha256 == VECTOR_RESULT_SHA and r.interval == (F(1, 6), F(5, 6))


def test_dropping_one_positive_source_leaves_five_without_interval():
    rows = tuple(C(k, "case", "run", int(v), 1) for k, v in pairs()[:5])
    agg = aggregate_metric(rows)
    assert agg.estimate == F(2, 5)
    r = sens(agg.source_values)
    assert r.groups == 5 and r.interval is None and r.draw_sha256 is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("seed", True),
        ("seed", -1),
        ("seed", 2**63),
        ("seed", 0.0),
        ("resamples", True),
        ("resamples", 99),
        ("resamples", 10001),
        ("resamples", 100.0),
    ],
)
def test_sensitivity_rejects_invalid_seed_and_resamples(field, value):
    with pytest.raises(ValueError):
        sens(pairs(), **{field: value})


def test_sensitivity_accepts_inclusive_bounds():
    assert sens(pairs(), seed=2**63 - 1, resamples=100).status == "descriptive"
    assert sens(pairs(), seed=0, resamples=10000).groups == 6


@pytest.mark.parametrize(
    "bad",
    [
        pairs() + (("source-a", F(1)),),  # duplicate key
        (("a", 0.5),) + pairs()[1:],  # float value
        (("a", True),) + pairs()[1:],  # bool value
        (("a", 1),) + pairs()[1:],  # plain int is not an exact Fraction
        tuple((f"s{i:03d}", F(i)) for i in range(257)),  # more than 256 sources
    ],
)
def test_sensitivity_rejects_invalid_source_values(bad):
    with pytest.raises(ValueError):
        sens(bad)
