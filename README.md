# ComplyScan

A local Python tool for reviewing supplied logs, configuration files, documents, and data exports for sensitive data, exposed secrets, insecure settings, and suspicious authentication activity. It links technical findings to candidate framework controls and produces an HTML report, with optional JSON and SARIF output.

**Scope:** This is automated evidence triage. Findings require analyst validation. No finding does not establish compliance, and the report is not a certification or audit opinion. The tool does not send scanned content to a network service.

## Quick start

Python 3.11 or newer is recommended. Basic text, log, CSV, and configuration scanning uses the standard library.
The original `compliance_scanner.py` command remains available as a compatibility entry point.

```bash
python complyscan.py list-frameworks
python complyscan.py list-checks
python complyscan.py scan -f pci-dss -f nist-csf -o report.html ./evidence/
```

For specialized formats, install only the dependencies you need:

```bash
python -m pip install -r requirements-optional.txt
```

The optional list covers Excel, PDF, legacy Excel, ODS, Parquet, EVTX, and YAML. If an optional library is unavailable, the affected file is reported as unable to evaluate; basic scanning continues. On Python 3.9 or 3.10, TOML falls back to line scanning because structural TOML parsing uses the Python 3.11+ `tomllib` module.

## CLI

```bash
python complyscan.py scan -f all \
  --json findings.json --sarif findings.sarif \
  --fail-on high -o report.html ./evidence/

python complyscan.py gui
```

`--fail-on high` returns exit code 2 if an active high or critical finding exists. The GUI listens on `127.0.0.1:8377` by default and processes uploaded files locally. Do not bind it to a public network without additional access controls.

### Baselines

```bash
python complyscan.py scan -f all --write-baseline baseline.json ./evidence/
# Review entries, document reasons and optionally set expires.
python complyscan.py scan -f all --baseline baseline.json -o report.html ./evidence/
```

Baselines are intended for reviewed exceptions. Version 1 baselines are accepted; new baselines use relative paths where possible. Expired suppressions no longer hide findings. Keep baseline files out of public repositories if they expose sensitive context.

## Input and output

Supported inputs include text/log files, compressed text logs (`.gz`), JSON, YAML, TOML, INI, `.env`, CSV/TSV, Excel, ODS, PDF, Parquet, and EVTX. The relevant optional package is loaded only for its file type. JSON, TOML, INI, `.env`, and YAML configuration values are parsed structurally for selected semantic checks when possible; parsing failures use line scanning.

The HTML report shows confidence separately from severity, candidate control mappings, scan coverage, and limits that reduced detail. JSON and SARIF provide machine-readable findings. Sensitive values are masked in reported evidence, but you should still review reports before sharing because paths, locations, and surrounding context may be sensitive.

Mapping provenance is explicit: a small set of NIST CSF 2.0 relationships is source reviewed and labeled *supporting*. The remaining legacy mappings are *unreviewed, inferred* candidates. No mapping claims independent certification or legal interpretation.

## Run tests

```bash
python -m unittest discover -s tests -v
```

The included workflow runs these tests and checks Python syntax on pushes and pull requests.

## Known limits

- This is pattern and heuristic based analysis; it can miss issues or flag benign data.
- Encrypted documents, image-only PDFs, and other content without extractable text need other review methods.
- Large scans cap items per file, distinct stored evidence, and scan-wide finding detail. The report shows omitted detail counts. Authentication actor state may also be evicted on high-cardinality logs.
- Structured config parsing is bounded by file size; larger configs use line scanning. YAML parsing needs the optional safe parser.
- Framework coverage varies. Most legacy control references have not received source review.
- The bundled tests cover key regression scenarios, not measured precision and recall across production evidence.

## Publishing this repository

Extract the ZIP, then create a new GitHub repository and upload its contents. To use Git locally:

```bash
git init
git add .
git commit -m "Initial ComplyScan release"
git branch -M main
git remote add origin https://github.com/YOUR-ACCOUNT/complyscan.git
git push -u origin main
```

Replace the example remote with your new repository URL. Add a license only after choosing the terms under which you want to share or accept contributions.
