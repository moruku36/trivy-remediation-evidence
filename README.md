# trivy-remediation-evidence

Generate deterministic JSON evidence and Japanese/English Markdown comparisons from Trivy image reports and explicit scan manifests.

## Install

Requires Python 3.11 or later.

```sh
python -m pip install .
```

## Compare

```sh
trivy-remediation-evidence compare --before before.json --after after.json --before-manifest before.manifest.json --after-manifest after.manifest.json --out-dir comparison
```

The output directory must be new. Outputs are `evidence.json`, `report.ja.md`, and `report.en.md`. Exit codes: 0 comparable, 2 comparison unavailable, 1 input/output or invocation error.

Package versions do not form part of finding identity. Matching scanner, database snapshot, effective configuration, target and scanned scope evidence are required. Missing or inconsistent evidence prevents a remediation comparison. “Not detected in this scan” does not establish remediation.

## Development

```sh
python -m pip install ".[dev]"
python -m pytest -q
```

Contract schemas are in `outputs/schemas/`; synthetic fixtures are in `outputs/fixtures/`. `integration_samples/` contains an optional fixed-sample OCI image builder and Trivy collector for localhost-only validation. It requires independently verified official Trivy 0.75.0, matching source archives, and the exact database snapshot pinned in the collector. Downloaded tools and databases are not included. It does not start containers and is not a general production collector.

This repository starts with a new independent history and contains tool code, contracts, synthetic fixtures and tests only.
