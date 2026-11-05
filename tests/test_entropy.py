import math

from hypothesis import given
from hypothesis import strategies as st

from secretscan.entropy import shannon_entropy


def test_empty_and_constant_strings_have_zero_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_two_equally_likely_symbols_is_one_bit():
    assert shannon_entropy("abab") == 1.0


def test_uniform_hex_alphabet_is_four_bits():
    assert math.isclose(shannon_entropy("0123456789abcdef"), 4.0)


@given(st.text(min_size=1, max_size=200))
def test_entropy_is_bounded_by_log2_of_distinct_symbols(s):
    h = shannon_entropy(s)
    assert -1e-9 <= h <= math.log2(len(set(s))) + 1e-9 if len(set(s)) > 1 else h == 0
