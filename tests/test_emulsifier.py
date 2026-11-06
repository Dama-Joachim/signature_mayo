"""Tests for MAYO polynomial indices and emulsifier matrices."""

from core.matrix import matrix_multiply
from scheme.emulsifier import (
    F_TAIL,
    build_E,
    ell_index,
    z_power_matrices,
)


def test_ell_indices_cover_all_pairs_without_duplicates() -> None:
    """Every upper-triangular pair maps to exactly one consecutive index."""
    k = 10
    indices = [
        ell_index(i, j, k)
        for i in range(k)
        for j in range(i, k)
    ]
    assert sorted(indices) == list(range(k * (k + 1) // 2))
    assert ell_index(0, k - 1, k) == 0


def test_power_matrices_follow_the_existing_polynomial_reduction() -> None:
    """Power matrices chain by multiplication and reduce z^m to the tail."""
    m = 8
    powers = z_power_matrices(m, 12)
    identity = [[1 if row == col else 0 for col in range(m)] for row in range(m)]
    assert powers[0] == identity
    for index in range(11):
        assert powers[index + 1] == matrix_multiply(powers[1], powers[index])
    assert [row[0] for row in powers[m]] == F_TAIL + [0] * (m - len(F_TAIL))


def test_build_e_is_symmetric_and_has_expected_dimensions() -> None:
    """The emulsifier table has symmetric entries of the configured size."""
    table = build_E(80, 10)
    assert len(table) == 10
    assert all(len(row) == 10 for row in table)
    assert all(table[i][j] == table[j][i] for i in range(10) for j in range(10))
    assert all(
        len(table[i][j]) == 80 and len(table[i][j][0]) == 80
        for i in range(10)
        for j in range(10)
    )
