
import secrets
import hashlib

from mayo_operation import add, subtract, multiply, inverse
from mayo_matrice import (
    matrix_add,
    matrix_transpose,
    matrix_multiply
)


# paramétre de MAYO1

Q = 16
N = 88
M = 80
O_DIM = 8
K = 10

SEED_SK_BYTES = 24
SEED_PK_BYTES = 16

V = N - O_DIM


# vérification des paramètre

def check_parameters():
    assert Q == 16
    assert V == 80
    assert V >= M
    assert K * O_DIM >= M

    print("Parametres MAYO1 valides !")


# création d'une matrice nulle

def zero_matrix(rows, cols):
    return [
        [0 for _ in range(cols)]
        for _ in range(rows)
    ]


# extraction de la matrice triangulaire superieure

def upper_triangle(A):

    if not A or not A[0]:
        raise ValueError("Matrice vide")

    if len(A) != len(A[0]):
        raise ValueError("La matrice doit etre carree")

    size = len(A)

    return [
        [
            A[i][j] if j >= i else 0
            for j in range(size)
        ]
        for i in range(size)
    ]


# generation d'une grainde secrete

def generate_secret_seed():
    return secrets.token_bytes(SEED_SK_BYTES)


# derivation des donnees à partir de SHAKE256

def derive_key_material(seed_sk):

    if len(seed_sk) != SEED_SK_BYTES:
        raise ValueError("Taille incorrecte de seed_sk")

    o_bytes = (V * O_DIM + 1) // 2

    output_length = SEED_PK_BYTES + o_bytes

    output = hashlib.shake_256(seed_sk).digest(output_length)

    seed_pk = output[:SEED_PK_BYTES]

    encoded_O = output[SEED_PK_BYTES:]

    return seed_pk, encoded_O


# 7. PREMIER TEST DE KEYGEN

def test_keygen():

    print("===== TEST KEYGEN MAYO1 =====")

    check_parameters()

    seed_sk = generate_secret_seed()

    seed_pk, encoded_O = derive_key_material(seed_sk)

    print("Taille seed_sk :", len(seed_sk), "octets")
    print("Taille seed_pk :", len(seed_pk), "octets")
    print("Taille O encodee :", len(encoded_O), "octets")

    print("Generation des graines reussie !")


if __name__ == "__main__":
    test_keygen()
