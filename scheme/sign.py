"""MAYO signing orchestration, separated from user-interface concerns."""

from core.field import add
from core.matrix import (
    Matrix,
    matrix_add,
    matrix_multiply,
    matrix_transpose,
    matrix_vector_multiply,
    vector_dot,
    vector_subtract,
)
from crypto.encoding import decode_vector, encode_vector
from crypto.hashing import derive_t_and_lambda, shake256
from crypto.randomness import random_bytes
from keys.expand_secret import parse_esk
from keys.parameters import (
    DIGEST_BYTES,
    K,
    M,
    N,
    O_DIM,
    R_BYTES,
    SALT_BYTES,
    V,
)
from scheme.emulsifier import get_E
from scheme.sample_solution import sample_solution


def add_block(A: Matrix, block_index: int, B: Matrix) -> None:
    """Add an ``M x O_DIM`` matrix into one column block of ``A`` in place.

    Args:
        A: Matrix with ``K`` column blocks.
        block_index: Zero-based block to update.
        B: Matrix to add into the selected block.
    """
    base = block_index * O_DIM
    for row in range(M):
        for col in range(O_DIM):
            A[row][base + col] = add(A[row][base + col], B[row][col])


def sign(esk: bytes, message: bytes | str) -> bytes:
    """Generate a MAYO signature using an expanded secret key.

    Args:
        esk: Expanded secret key in the existing encoded format.
        message: Message bytes or text to sign.

    Returns:
        Signature bytes containing the encoded vector followed by its salt.

    Raises:
        RuntimeError: If no solution is found within the existing 256 retries.
        ValueError: If the expanded secret key or input dimensions are invalid.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")

    seed_sk, O, P1, L = parse_esk(esk)
    m_digest = shake256(message, DIGEST_BYTES)

    r_val = random_bytes(R_BYTES)
    salt_input = m_digest + r_val + seed_sk
    salt = shake256(salt_input, SALT_BYTES)
    t, Lambda = derive_t_and_lambda(m_digest, salt, M, N)

    Lambda_v = [row[:V] for row in Lambda]
    Lambda_o = [row[V:] for row in Lambda]
    E = get_E()

    for ctr in range(256):
        v_bytes_len = K * (V // 2)
        r_bytes_len = (K * O_DIM + 1) // 2
        v_seed_input = m_digest + salt + seed_sk + bytes([ctr])
        v_output = shake256(v_seed_input, v_bytes_len + r_bytes_len)

        v_list = []
        for i in range(K):
            vi_bytes = v_output[i * (V // 2):(i + 1) * (V // 2)]
            v_list.append(decode_vector(V, vi_bytes))

        r = decode_vector(K * O_DIM, v_output[v_bytes_len:])

        M_matrices = []
        for i in range(K):
            Mi = [[0] * O_DIM for _ in range(M)]
            vi = v_list[i]
            for j in range(M):
                Mi[j] = matrix_vector_multiply(matrix_transpose(L[j]), vi)
            M_matrices.append(Mi)

        M_matrices[0] = matrix_add(
            matrix_add(M_matrices[0], matrix_multiply(Lambda_v, O)),
            Lambda_o,
        )

        y = list(t)
        W = [
            [matrix_vector_multiply(P1[a], vj) for a in range(M)]
            for vj in v_list
        ]
        A = [[0] * (K * O_DIM) for _ in range(M)]

        for i in range(K):
            vi = v_list[i]
            lam_v_vi = matrix_vector_multiply(Lambda_v, vi)
            y = vector_subtract(
                y,
                matrix_vector_multiply(E[i][0], lam_v_vi),
            )

            for j in range(i, K):
                vj = v_list[j]
                u = []
                for a in range(M):
                    term = vector_dot(vi, W[j][a])
                    if i != j:
                        term = add(term, vector_dot(vj, W[i][a]))
                    u.append(term)

                y = vector_subtract(y, matrix_vector_multiply(E[i][j], u))
                add_block(A, i, matrix_multiply(E[i][j], M_matrices[j]))
                if i != j:
                    add_block(A, j, matrix_multiply(E[i][j], M_matrices[i]))

        x = sample_solution(A, y, r)
        if x is not None:
            s_list = []
            for i in range(K):
                xi_block = x[i * O_DIM:(i + 1) * O_DIM]
                oxi = matrix_vector_multiply(O, xi_block)
                vi_plus_oxi = [
                    add(v_list[i][index], oxi[index])
                    for index in range(V)
                ]
                s_list.extend(vi_plus_oxi + xi_block)

            return encode_vector(s_list) + salt

    raise RuntimeError(
        "Échec de la signature après 256 tentatives (Retry Limit atteint)."
    )
