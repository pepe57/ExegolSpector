<div align="center">

<img src="assets/excalibur_logo.png" alt="Excalibur" width="320" />

# Excalibur

**Interface agentique entre Hermes et [nuclei](https://github.com/projectdiscovery/nuclei) — l'outil qui transforme un scan brut en rapport de bug bounty prêt à soumettre.**

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](#)
[![nuclei](https://img.shields.io/badge/engine-nuclei-6B4FBB.svg)](https://github.com/projectdiscovery/nuclei)
[![MCP](https://img.shields.io/badge/interface-MCP-a855f7.svg)](https://modelcontextprotocol.io)
[![tests](https://img.shields.io/badge/tests-10%2F10-22c55e.svg)](#tests)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

</div>

---

## Pourquoi

`nuclei` détecte. Il ne rédige pas. Sa sortie JSONL est brute, dupliquée, mélangée
(info + vraies vulns), et hors-scope non filtré. Les plateformes (YesWeHack,
Immunefi, HackerOne) veulent l'inverse : un rapport structuré, dédupliqué,
**dans le scope**, avec preuve de reproduction.

Excalibur est la couche manquante :

```
cible → nuclei → parse → dédup → SCOPE → rapport Markdown de soumission
```

Il ne réinvente aucun scanner. Il pilote `nuclei` (le vrai moteur) et produit
la seule chose que `nuclei` ne fait pas : un livrable prêt à copier-coller.

## Architecture

```text
Hermes (agent)
     │  MCP stdio
     ▼
excalibur_mcp.py          ← 3 outils : scan · report · scope_check
     │
     ▼
excalibur.py              ← moteur : run_nuclei → parse_jsonl → apply_scope → build_report
     │
     ▼
nuclei -jsonl             ← moteur de détection (ProjectDiscovery)
```

Découpage volontaire (**loop engineering**) : le code déterministe fait le
mécanique (scan, parse, scope, format) — fiable et gratuit en tokens ;
l'agent fait le jugement (choisir la cible, trier, décider de soumettre).

## Fonctionnalités

- **Orchestration nuclei** — tags/severity configurables, cap de timeout
- **Déduplication** — nuclei répète le même template sur plusieurs matchers ; Excalibur fusionne
- **Scope enforcement** — include/exclude en globs, résistant au suffix-spoofing (`x.com.attacker.net` rejeté)
- **Séparation actionnable / info** — les détections `info` vont en appendice, pas dans le rapport
- **Rapport de soumission** — titre, sévérité, CVE/CWE, reproduction `curl`, remediation, références
- **Sortie JSON + exit codes** — `0` = rien d'actionnable, `2` = findings actionnables (pilotage de loop)
- **Serveur MCP** — branché directement dans Hermes

## Installation

Aucune dépendance lourde. Il faut `nuclei` sur le PATH et [`uv`](https://github.com/astral-sh/uv) :

```bash
brew install nuclei      # ou : go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

## Usage — CLI

```bash
# Scanner une cible et produire un rapport
python3 excalibur.py -u https://target.com --scope scope.yaml \
    --program "Acme YWH" --platform ywh --json -o out/

# Rapporter depuis un scan nuclei existant
python3 excalibur.py --jsonl scan.jsonl -u target.com --scope scope.yaml
```

Fichier de scope (`scope.yaml`) :

```yaml
include:
  - "*.target.com"
  - "target.com"
exclude:
  - "admin.target.com"
```

## Usage — MCP (dans Hermes)

`~/.hermes/config.yaml` :

```yaml
mcp_servers:
  - name: excalibur
    transport: stdio
    command: uv
    args: ["run", "/Users/you/projects/excalibur/excalibur_mcp.py"]
    enabled: true
```

Outils exposés :

| Outil | Rôle |
|-------|------|
| `excalibur_scan` | Lance nuclei sur une cible, renvoie un handle |
| `excalibur_report` | Parse un run en rapport scope-enforced |
| `excalibur_scope_check` | Vérifie qu'un host est dans le scope (avant d'agir) |

## Tests

```bash
uv run --with pytest python3 -m pytest test_excalibur.py -v
```

Couvre : déduplication, robustesse (JSON invalide/lignes vides), tri par
sévérité, extraction CVE/CWE/curl, scope include/exclude, anti-spoof, rendu du rapport.

## Licence

Apache 2.0.
