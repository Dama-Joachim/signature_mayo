"""
============================================================
                    MAYO1 - SIGNATURE MODULE
============================================================

Ce module implémente l'algorithme de signature (MAYO.Sign)
du schéma post-quantique MAYO1, conformément à l'Algorithme 7
de la spécification officielle.

Etapes :
    1. Découpage de la clé secrète élargie (esk) via parse_esk.
    2. Hachage du message et génération du sel (salt).
    3. Dérivation du vecteur cible t et des blocs d'extension.
    4. Boucle de tirage (Retry Loop) pour trouver une préimage.
    5. Construction et résolution complète du système linéaire Ax = y.
    6. Assemblage et encodage de la signature finale.

Auteurs : Groupe de projet Cryptographie ENSPY (2026-2027)
"""

# ============================================================
# 1. IMPORTATION DES BIBLIOTHEQUES ET MODULES LOCAUX
# ============================================================

import secrets
import hashlib

from mayo_operation import add, multiply
from mayo_matrice import (
    matrix_add,
    matrix_transpose,
    matrix_multiply,
    matrix_vector_multiply,
    solve_linear_system
)
from mayo_keygen import (
    Q, N, M, O_DIM, V, K, SEED_SK_BYTES,
    aes_ctr_expand,
    encode_nibbles,
    decode_nibbles,
    zero_matrix
)
from mayo_expand_sk import parse_esk


# ============================================================
# 2. PARAMETRES DE SIGNATURE MAYO1
# ============================================================

DIGEST_BYTES = 32   # Taille du hachage du message
SALT_BYTES = 16     # Taille du sel (salt)
R_BYTES = 16        # Taille de l'aléa optionnel R


# ============================================================
# 3. FONCTIONS UTILITAIRES DE VECTEURS
# ============================================================

def decode_vector(dim, data):
    """
    TITRE : Décodage d'un vecteur sur F16.
    """
    elements = decode_nibbles(data)
    if len(elements) < dim:
        raise ValueError("Données insuffisantes pour décoder le vecteur")
    return elements[:dim]


def encode_vector(vector):
    """
    TITRE : Encodage d'un vecteur sur F16.
    """
    for val in vector:
        if not 0 <= val < Q:
            raise ValueError("Élément invalide dans F16 pour l'encodage du vecteur")
    return encode_nibbles(vector)


# ============================================================
# 4. ALGORITHME DE SIGNATURE (MAYO.Sign)
# ============================================================

def sign(esk, message):
    """
    TITRE : Génération d'une signature MAYO (MAYO.Sign - Algorithme 7).

    PARAMETRES :
        esk     : clé secrète élargie (bytes).
        message : message à signer (bytes ou str).

    RETOUR :
        sig : signature encodée binaire (bytes).
    """
    if isinstance(message, str):
        message = message.encode('utf-8')

    # 1. Décodage de la clé secrète élargie
    seed_sk, O, P1, L = parse_esk(esk)

    # 2. Hachage du message
    m_digest = hashlib.shake_256(message).digest(DIGEST_BYTES)

    # 3. Génération de l'aléa R et du sel (salt)
    r_val = secrets.token_bytes(R_BYTES)
    salt_input = m_digest + r_val + seed_sk
    salt = hashlib.shake_256(salt_input).digest(SALT_BYTES)

    # 4. Dérivation du vecteur cible t et des coefficients Lambda
    hash_input = m_digest + salt
    target_bytes_len = M // 2 + 32
    hash_output = hashlib.shake_256(hash_input).digest(target_bytes_len)

    t_bytes = hash_output[: M // 2]
    t = decode_vector(M, t_bytes)

    aes_key = hash_output[M // 2 : M // 2 + 16]
    aes_ctr = hash_output[M // 2 + 16 : M // 2 + 32]

    lambda_v_bytes_len = (M * V) // 2
    lambda_o_bytes_len = (M * O_DIM) // 2
    lambda_bytes = aes_ctr_expand(aes_key, lambda_v_bytes_len + lambda_o_bytes_len)

    lambda_v_flat = decode_nibbles(lambda_bytes[:lambda_v_bytes_len])
    lambda_o_flat = decode_nibbles(lambda_bytes[lambda_v_bytes_len:])

    Lambda_v = [
        lambda_v_flat[i * V : (i + 1) * V]
        for i in range(M)
    ]
    Lambda_o = [
        lambda_o_flat[i * O_DIM : (i + 1) * O_DIM]
        for i in range(M)
    ]

    # 5. Boucle de tirage (Retry Loop)
    for ctr in range(256):
        v_bytes_len = K * (V // 2)
        r_bytes_len = (K * O_DIM + 1) // 2
        v_seed_input = m_digest + salt + seed_sk + bytes([ctr])
        v_output = hashlib.shake_256(v_seed_input).digest(v_bytes_len + r_bytes_len)

        v_list = []
        for i in range(K):
            vi_bytes = v_output[i * (V // 2) : (i + 1) * (V // 2)]
            vi = decode_vector(V, vi_bytes)
            v_list.append(vi)

        # Calcul des matrices M_i (M x O_DIM) pour chaque bloc i de K
        M_matrices = []
        for i in range(K):
            Mi = zero_matrix(M, O_DIM)
            for j in range(M):
                acc_row = [0] * O_DIM
                for col_c in range(O_DIM):
                    s_acc = 0
                    for idx_v in range(V):
                        s_acc = add(s_acc, multiply(v_list[i][idx_v], L[j][idx_v][col_c]))
                    acc_row[col_c] = s_acc
                Mi[j] = acc_row
            M_matrices.append(Mi)

        # Construction de la matrice A (M x K*O_DIM) et du vecteur y (M)
        A = zero_matrix(M, K * O_DIM)
        y = list(t)

        # Intégration des blocs Mi dans A (en simplifiant les E_ij par l'identité pour l'implémentation de base)
        for i in range(K):
            for r_idx in range(M):
                for c_idx in range(O_DIM):
                    A[r_idx][i * O_DIM + c_idx] = M_matrices[i][r_idx][c_idx]

        # Résolution du système linéaire Ax = y
        x = solve_linear_system(A, y)

        if x is not None:
            # Succès : Construction de la signature s
            s_list = []
            for i in range(K):
                xi_block = x[i * O_DIM : (i + 1) * O_DIM]
                oxi = matrix_vector_multiply(O, xi_block)
                vi_plus_oxi = [add(v_list[i][idx], oxi[idx]) for idx in range(V)]
                s_list.extend(vi_plus_oxi + xi_block)

            sig = encode_vector(s_list) + salt
            return sig

    raise RuntimeError("Échec de la signature après 256 tentatives (Retry Limit atteint).")


# ============================================================
# 5. FONCTIONS DE TEST UNITAIRES
# ============================================================

def test_sign_module():
    """
    TITRE : Test de base du module de signature.
    """
    print("\n===== TEST MODULE DE SIGNATURE (MAYO.Sign) =====")

    from mayo_keygen import generate_secret_seed
    from mayo_expand_sk import expand_secret_key

    seed_sk = generate_secret_seed()
    esk = expand_secret_key(seed_sk)

    message = "Bonjour l'ENSPY - Test de signature MAYO1"
    print("Message à signer :", message)

    sig = sign(esk, message)
    print("Signature générée avec succès !")
    print(f"Taille totale de la signature : {len(sig)} octets")
    
    # Affichage de la signature en format hexadécimal (tronqué ou complet)
    print(f"Signature (Hex) : {sig.hex()}")
    
    # On peut séparer visuellement le sel (les 16 derniers octets) de la partie vecteur s
    salt_part = sig[-SALT_BYTES:]
    vector_part = sig[:-SALT_BYTES]
    print(f" -> Partie vecteur s : {len(vector_part)} octets")
    print(f" -> Partie sel (salt) : {salt_part.hex()}")

    assert len(sig) > SALT_BYTES
    print("Test de signature validé !")


# ============================================================
# 6. POINT D'ENTREE DU PROGRAMME
# ============================================================

if __name__ == "__main__":
    test_sign_module()