"""AES-based counter-mode byte expansion used by the MAYO implementation."""

from Crypto.Cipher import AES


def aes_ctr_expand(seed_pk: bytes, output_length: int) -> bytes:
    """Expand bytes using AES-128 with a counter starting at zero.

    The implementation encrypts consecutive 16-byte, big-endian counter
    blocks in ECB mode and concatenates the results, preserving the existing
    MAYO project's counter convention.

    Args:
        seed_pk: The 16-byte AES-128 key.
        output_length: Number of output bytes requested.

    Returns:
        Exactly ``output_length`` bytes.

    Raises:
        ValueError: If the key is not 16 bytes or the requested length is
            negative.
    """
    if len(seed_pk) != 16:
        raise ValueError("seed_pk doit contenir 16 octets")

    if output_length < 0:
        raise ValueError("Longueur de sortie invalide")

    aes = AES.new(seed_pk, AES.MODE_ECB)
    output = bytearray()
    counter = 0

    while len(output) < output_length:
        counter_block = counter.to_bytes(16, byteorder="big")
        output.extend(aes.encrypt(counter_block))
        counter += 1

    return bytes(output[:output_length])


def aes_ctr_expand_iv(key: bytes, iv: bytes, output_length: int) -> bytes:
    """Expand bytes using AES-128 and a caller-provided initial counter.

    Counter blocks are the big-endian integer represented by ``iv``, followed
    by successive integers modulo 2**128. This preserves the convention used
    by the original signing implementation.

    Args:
        key: The 16-byte AES-128 key.
        iv: The 16-byte initial counter block.
        output_length: Number of output bytes requested.

    Returns:
        The requested prefix of the encrypted counter stream.

    Raises:
        ValueError: If either ``key`` or ``iv`` is not 16 bytes.
    """
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("key et iv doivent contenir 16 octets")

    aes = AES.new(key, AES.MODE_ECB)
    counter = int.from_bytes(iv, byteorder="big")
    output = bytearray()

    while len(output) < output_length:
        counter_block = (counter % (1 << 128)).to_bytes(16, byteorder="big")
        output.extend(aes.encrypt(counter_block))
        counter += 1

    return bytes(output[:output_length])
