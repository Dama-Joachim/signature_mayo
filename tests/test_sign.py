"""Tests for sample-solution and signature generation."""

import pytest

from core.matrix import matrix_vector_multiply
from keys.expand_secret import expand_secret_key
from keys.parameters import K, O_DIM, SALT_BYTES, SEED_SK_BYTES, V
from scheme.sample_solution import sample_solution
from scheme.sign import sign


def test_sample_solution_solves_and_rejects_inconsistent_systems() -> None:
    """SampleSolution returns a satisfying vector or None for inconsistency."""
    matrix = [[1, 0, 1], [0, 1, 1]]
    target = [5, 3]
    random_vector = [2, 4, 6]
    solution = sample_solution(matrix, target, random_vector)

    assert solution is not None
    assert matrix_vector_multiply(matrix, solution) == target
    assert sample_solution([[1, 1], [1, 1]], [1, 2], [0, 0]) is None


def test_signature_uses_existing_encoding_and_length() -> None:
    """Signing yields the established 464-byte vector-plus-salt format."""
    seed_sk = bytes(range(SEED_SK_BYTES))
    expanded_secret = expand_secret_key(seed_sk)
    signature = sign(expanded_secret, "MAYO test message")

    assert len(signature) == (V + O_DIM) * K // 2 + SALT_BYTES


def test_sign_rejects_malformed_secret_key() -> None:
    """Sign propagates invalid expanded-key input as a value error."""
    with pytest.raises(ValueError):
        sign(b"short", b"message")
