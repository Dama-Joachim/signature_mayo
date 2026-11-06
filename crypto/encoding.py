"""Encoding and decoding helpers for GF(16) elements and vectors."""

from core.field import FIELD_SIZE


def decode_nibbles(data: bytes) -> list[int]:
    """Decode each byte into low-nibble then high-nibble field elements.

    Args:
        data: Bytes containing two packed GF(16) elements per byte.

    Returns:
        The unpacked elements in the existing low-then-high order.
    """
    elements = []
    for byte in data:
        elements.append(byte & 0x0F)
        elements.append((byte >> 4) & 0x0F)
    return elements


def encode_nibbles(elements: list[int]) -> bytes:
    """Pack GF(16) elements two per byte, low nibble first.

    An odd final element is packed with a zero high nibble, matching the
    existing key and signature encoding convention.

    Args:
        elements: Field elements to encode.

    Returns:
        The packed byte representation.

    Raises:
        ValueError: If any element is outside GF(16).
    """
    encoded = bytearray()

    for index in range(0, len(elements), 2):
        low = elements[index]
        if not 0 <= low < FIELD_SIZE:
            raise ValueError("Element invalide dans F16")

        if index + 1 < len(elements):
            high = elements[index + 1]
            if not 0 <= high < FIELD_SIZE:
                raise ValueError("Element invalide dans F16")
        else:
            high = 0

        encoded.append(low | (high << 4))

    return bytes(encoded)


def decode_vector(dim: int, data: bytes) -> list[int]:
    """Decode the first ``dim`` GF(16) elements from packed bytes.

    Extra decoded elements are ignored, as in the original signing module.

    Args:
        dim: Number of elements in the requested vector.
        data: Packed vector bytes.

    Returns:
        A vector containing ``dim`` field elements.

    Raises:
        ValueError: If the input does not contain enough elements.
    """
    elements = decode_nibbles(data)
    if len(elements) < dim:
        raise ValueError("Données insuffisantes pour décoder le vecteur")
    return elements[:dim]


def encode_vector(vector: list[int]) -> bytes:
    """Encode a vector of GF(16) elements in the existing nibble format.

    Args:
        vector: Field elements to pack.

    Returns:
        The low-nibble-first packed bytes.

    Raises:
        ValueError: If a vector element is outside GF(16).
    """
    for value in vector:
        if not 0 <= value < FIELD_SIZE:
            raise ValueError("Élément invalide dans F16 pour l'encodage du vecteur")
    return encode_nibbles(vector)
