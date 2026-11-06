"""MAYO signature verification, independent of the signing module."""

from core.matrix import matrix_vector_multiply, vector_add
from core.quadratic import evaluate_quadratic_form
from crypto.encoding import decode_vector
from crypto.hashing import derive_t_and_lambda, shake256
from keys.expand_public import parse_epk
from keys.parameters import DIGEST_BYTES, K, M, N, O_DIM, SALT_BYTES, V
from scheme.emulsifier import get_E


def verify(epk: bytes, message: bytes | str, sig: bytes) -> int:
    """Verify a signature using the expanded public key and original message.

    Args:
        epk: Expanded public-key bytes.
        message: Original message as bytes or text.
        sig: Encoded signature bytes.

    Returns:
        ``0`` if valid, otherwise ``-1``.
    """
    if isinstance(message, str):
        message = message.encode("utf-8")

    try:
        P1, P2, P3 = parse_epk(epk)
    except Exception:
        return -1

    expected_s_bytes = (K * N + 1) // 2
    if len(sig) != expected_s_bytes + SALT_BYTES:
        return -1

    s_bytes = sig[:expected_s_bytes]
    salt = sig[expected_s_bytes:expected_s_bytes + SALT_BYTES]

    try:
        s_elements = decode_vector(K * N, s_bytes)
    except Exception:
        return -1

    s_blocks = [
        s_elements[index * N:(index + 1) * N]
        for index in range(K)
    ]

    m_digest = shake256(message, DIGEST_BYTES)
    try:
        t, Lambda = derive_t_and_lambda(m_digest, salt, M, N)
    except Exception:
        return -1

    E = get_E()
    y = evaluate_quadratic_form(P1, P2, P3, s_blocks, V, O_DIM, K, M, E)

    for i in range(K):
        linear_val = matrix_vector_multiply(Lambda, s_blocks[i])
        y = vector_add(y, matrix_vector_multiply(E[0][i], linear_val))

    return 0 if y == t else -1
