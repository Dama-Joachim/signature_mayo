"""Linear-system solvers over GF(16)."""

from core.field import inverse, multiply, subtract
from core.matrix import Matrix, Vector


def solve_linear_system(A: Matrix, b: Vector) -> Vector | None:
    """Solve ``A*x = b`` by Gaussian elimination over GF(16).

    When the system has multiple solutions, free variables are set to zero.

    Args:
        A: Non-empty coefficient matrix.
        b: Right-hand side vector with one element per row in ``A``.

    Returns:
        One solution vector, or ``None`` if the system is inconsistent.

    Raises:
        ValueError: If ``A`` is empty or ragged, or ``b`` has the wrong
            length.
    """
    if not A or not A[0]:
        raise ValueError("La matrice A ne doit pas etre vide")

    rows = len(A)
    cols = len(A[0])

    if any(len(row) != cols for row in A):
        raise ValueError("Matrice A invalide")

    if len(b) != rows:
        raise ValueError("Dimensions incompatibles")

    augmented = [list(A[i]) + [b[i]] for i in range(rows)]
    pivot_columns = []
    pivot_row = 0

    for col in range(cols):
        selected = None
        for row_index in range(pivot_row, rows):
            if augmented[row_index][col] != 0:
                selected = row_index
                break

        if selected is None:
            continue

        augmented[pivot_row], augmented[selected] = (
            augmented[selected],
            augmented[pivot_row],
        )

        pivot = augmented[pivot_row][col]
        inv_pivot = inverse(pivot)
        augmented[pivot_row] = [
            multiply(value, inv_pivot) for value in augmented[pivot_row]
        ]

        for row_index in range(rows):
            if row_index != pivot_row:
                factor = augmented[row_index][col]
                if factor != 0:
                    for column_index in range(cols + 1):
                        augmented[row_index][column_index] = subtract(
                            augmented[row_index][column_index],
                            multiply(
                                factor,
                                augmented[pivot_row][column_index],
                            ),
                        )

        pivot_columns.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break

    for row_index in range(rows):
        if all(augmented[row_index][col] == 0 for col in range(cols)):
            if augmented[row_index][cols] != 0:
                return None

    solution = [0] * cols
    for row_index, col in enumerate(pivot_columns):
        solution[col] = augmented[row_index][cols]

    return solution
