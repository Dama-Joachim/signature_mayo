# MAYO1 Lab

Projet pédagogique en Python organisé autour d'une implémentation existante du
schéma de signature MAYO1. Les calculs cryptographiques sont séparés de
l'orchestration et de l'affichage afin de faciliter leur test et une éventuelle
interface pédagogique ultérieure.

> **Important :** ce projet n'est ni une implémentation certifiée ni une
> affirmation de conformité à la spécification officielle MAYO Round 3. Les
> paramètres et les encodages de l'implémentation d'origine ont été préservés.
> Des points restent à confirmer par comparaison à des vecteurs officiels,
> notamment la valeur `F_TAIL = [8, 1, 1, 0]` et les conventions de compteur
> utilisées pour l'expansion AES. Ne l'utilisez pas pour protéger des données
> réelles.

## Architecture

```text
core/       Arithmétique GF(16), matrices, algèbre linéaire et formes quadratiques
crypto/     AES, aléatoire, hachage et encodage
keys/       Paramètres, génération et expansion des clés
scheme/     Émulsificateur, recherche de solution, signature et vérification
tests/      Tests pytest isolés du code de production
app.py      Orchestration de démonstration, sans dépendance d'interface
main.py     Point d'entrée en ligne de commande
mayo_*.py   Façades de compatibilité pour les anciens imports
```

`app.run_demo(message)` retourne un `DemoResult` contenant les clés compactes
et étendues, la signature et le résultat de vérification. Les fonctions
cryptographiques ne dépendent pas de Streamlit ni d'une autre interface.

## Installation

Python 3.10 ou plus récent est requis.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Sous Windows, activez l'environnement avec `.venv\Scripts\activate`.

## Exécution

Depuis la racine du dépôt :

```bash
python main.py
python main.py "message à signer"
```

La commande affiche les tailles des artefacts et le résultat de la vérification,
sans afficher les clés ni la signature.

## Tests

```bash
python -m pytest -v
```

Les tests vérifient les opérations de corps fini et de matrices, la génération
et l'expansion des clés, puis les chemins de signature et de vérification.

## Paramètres et encodages conservés

Les paramètres actuellement utilisés incluent `Q=16`, `N=88`, `M=80`,
`O_DIM=8`, `K=10`, des graines de 24 et 16 octets, et une signature de
464 octets. Les tailles et formats sont ceux de l'implémentation préexistante;
leur présence ici ne constitue pas une attestation de conformité normative.
