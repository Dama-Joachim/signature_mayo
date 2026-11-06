"""SHAKE256 hashing and MAYO byte-derivation routines."""

import hashlib

from crypto.aes import aes_ctr_expand_iv
from crypto.encoding import decode_nibbles, decode_vector


def shake256(data: bytes, output_length: int) -> bytes:
    """Return a fixed-length SHAKE256 digest.

    Args:
        data: Input bytes.
        output_length: Number of digest bytes requested.

    Returns:
        The requested SHAKE256 digest bytes.
    """
    return hashlib.shake_256(data).digest(output_length)


def derive_key_material(
    seed_sk: bytes,
    seed_sk_bytes: int,
    seed_pk_bytes: int,
    vinegar_dim: int,
    oil_dim: int,
) -> tuple[bytes, bytes]:
    """Derive the public seed and encoded oil matrix from the secret seed.

    Args:
        seed_sk: Secret seed.
        seed_sk_bytes: Required secret-seed length.
        seed_pk_bytes: Number of derived public-seed bytes.
        vinegar_dim: Number of vinegar rows in the oil matrix.
        oil_dim: Number of oil columns in the matrix.

    Returns:
        The derived public seed and encoded oil matrix bytes.

    Raises:
        ValueError: If ``seed_sk`` has a length different from
            ``seed_sk_bytes``.
    """
    if len(seed_sk) != seed_sk_bytes:
        raise ValueError("Taille incorrecte de seed_sk")

    oil_bytes = (vinegar_dim * oil_dim) // 2
    output = shake256(seed_sk, seed_pk_bytes + oil_bytes)
    return output[:seed_pk_bytes], output[seed_pk_bytes:]


def derive_t_and_lambda(
    m_digest: bytes,
    salt: bytes,
    polynomial_count: int,
    variable_count: int,
) -> tuple[list[int], list[list[int]]]:
    """Derive the target vector and Lambda matrix used by Sign and Verify.

    Args:
        m_digest: Fixed-length digest of the message.
        salt: Signature salt.
        polynomial_count: Number of target equations.
        variable_count: Number of variables in each Lambda row.

    Returns:
        The target vector and a ``polynomial_count x variable_count`` matrix.
    """
    hash_input = m_digest + salt
    target_bytes_len = polynomial_count // 2 + 32
    hash_output = shake256(hash_input, target_bytes_len)

    target_bytes = hash_output[: polynomial_count // 2]
    target = decode_vector(polynomial_count, target_bytes)

    aes_key = hash_output[polynomial_count // 2 : polynomial_count // 2 + 16]
    aes_iv = hash_output[
        polynomial_count // 2 + 16 : polynomial_count // 2 + 32
    ]

    lambda_bytes = aes_ctr_expand_iv(
        aes_key,
        aes_iv,
        (polynomial_count * variable_count) // 2,
    )
    lambda_flat = decode_nibbles(lambda_bytes)
    lambda_matrix = [
        lambda_flat[index * variable_count : (index + 1) * variable_count]
        for index in range(polynomial_count)
    ]

    return target, lambda_matrix
