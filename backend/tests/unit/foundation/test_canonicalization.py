import pytest

from app.events.service import canonical_json, request_hash


@pytest.mark.unit
def test_cross_runtime_json_subset_has_fixed_unicode_and_numeric_vectors() -> None:
    decomposed = "Cafe\u0301"
    arguments = {"name": decomposed, "count": 9_007_199_254_740_991}
    assert canonical_json(arguments) == '{"count":9007199254740991,"name":"Café"}'
    assert request_hash("1", arguments) == (
        "02dc88e35e4329de1aa34362ff2dc92275d358f70f33a7b5f00dea465510f5f8"
    )


@pytest.mark.unit
@pytest.mark.parametrize("value", [1.5, 9_007_199_254_740_992])
def test_ambiguous_numeric_arguments_are_rejected(value: object) -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": value})
