# ChronicalGraph
Converts Log2Timeline into an Evidence Graph

CronicleGraph turns Plaso JSON/JSONL timeline exports into explainable evidence
relationships and hypothesis-driven investigation reports. It is an independent
application that uses Plaso output as an input format; Plaso is not bundled.

The alpha release emphasizes deterministic analysis and provenance. Every finding
links back to the source event identifiers, and inferred relationships are marked
as inference rather than fact.

## Current capabilities

- Reads JSONL, a JSON array, one JSON event, or `{ "events": [...] }`
- Normalizes common Plaso field variants
- Extracts event, host, user, file, URL, domain, hash, and process entities
- Models timestamp confidence
- Correlates download-to-execution, USB-to-execution, and execution-to-persistence
- Evaluates built-in investigative hypotheses
- Produces a searchable, self-contained HTML report
- Requires only Python 3.11 or newer

## Quick start

Run directly from the repository:

```bash
python -m chroniclegraph inspect tests/fixtures/sample_plaso.jsonl
python -m chroniclegraph analyze tests/fixtures/sample_plaso.jsonl \
  --output chronicle-report.html
```

Or install the command in an isolated virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
chroniclegraph analyze timeline.jsonl -o report.html
```

Export a Plaso storage file to JSONL before analysis:

```bash
psort.py -o json_line -w timeline.jsonl timeline.plaso
chroniclegraph analyze timeline.jsonl -o report.html
```

## Analysis model

Observed edges mean a value appeared directly in a source event. Inferred edges
require semantic event types, a shared path, chronological ordering, and a bounded
time window. A confidence score is derived from the weaker source timestamp and a
correlation penalty. This score estimates evidence quality; it is not a probability
that malicious activity occurred.

ChronicleGraph currently uses intentionally conservative string classification.
Production deployments should replace or supplement this with tested mappings for
specific Plaso `data_type` values.

## Development

```bash
python -m unittest discover -s tests -v
```

Important next steps are a versioned normalized schema, configurable hypothesis
files, process-aware correlation, cross-host clock-skew correction, and a richer
interactive graph view.

## Evidence and security notes

- Work from forensic copies and preserve original evidence separately.
- Record the Plaso command, version, artifact definitions, and input hashes.
- Treat the HTML report as sensitive case data.
- Findings are investigative leads, not proof of intent or attribution.
- The report escapes event text before inserting it into HTML.

## License

Copyright 2026 ChronicleGraph contributors.

Licensed under the Apache License, Version 2.0. See `LICENSE`. Plaso is a separate
project distributed under its own Apache 2.0 license and copyright notices.
