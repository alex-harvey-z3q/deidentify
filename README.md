# Deidentify Bundle

`deidentify` is a local-first CLI for preparing a Git project or text bundle for external sharing. It does not modify the source directory. It supports a review workflow in which an approved internal AI proposes organisation-fingerprint entries and a person explicitly approves entries before they are transformed.

This is an initial implementation. It is a release aid, not a guarantee of anonymity.

## Workflow

1. Initialise an organisation fingerprint.
2. Scan a source directory to produce a local candidate report and a Copilot-review request.
3. Send the request only to your approved internal Copilot environment.
4. Import Copilot's structured response as `candidate` entries.
5. Review the fingerprint file and change vetted entries to `approved`.
6. Build a new tarball. The source directory stays untouched.

```bash
python -m pip install -e .

deidentify init fingerprint.json
deidentify scan /path/to/project --report scan-report.json --copilot-request copilot-request.json
# Send copilot-request.json to the approved internal service, then save its response.
deidentify import-review fingerprint.json copilot-response.json
# Edit fingerprint.json: set reviewed entries' status to "approved".
deidentify build /path/to/project fingerprint.json output/project-deidentified.tar.gz
```

## Fingerprint states

- `candidate`: proposed by a scanner or AI; never transformed.
- `approved`: a reviewer has confirmed the term is identifying; transformed.
- `ignored`: deliberately safe or generic; retained to avoid repeated review noise.

The fingerprint is sensitive organisational data. Keep it in an approved, access-controlled location and never include it in the exported archive.

## Copilot response format

Copilot should return JSON in this shape. It may only propose entries; it cannot approve them.

```json
{
  "entries": [
    {
      "canonical": "Orion Payments",
      "category": "internal_product",
      "variants": ["Orion", "orion-api", "ORION_SERVICE"],
      "confidence": "high",
      "rationale": "Appears as a service, deployment, and API prefix.",
      "evidence": [{"path": "services/orion/config.yml", "line": 4}]
    }
  ]
}
```

`category` is a safe identifier such as `company`, `internal_product`, `customer`, `internal_system`, or `project`. Replacement tokens are generated as `<CATEGORY_001>` per build and are consistent throughout that build. The original-to-token map is held in memory only and is not written to the manifest.

## Safety characteristics and limits

- `.git`, common secret files, binary files, large files, and build/vendor directories are excluded by default.
- Only UTF-8 text files are transformed; files that cannot be decoded are excluded and recorded in the manifest.
- The final staged output is checked for approved variants. Any unresolved occurrence blocks export.
- Candidate discovery identifies unusual terms, not proven corporate identity. A human review is required.
- This tool assumes secret scanning and PII/DLP controls are enforced elsewhere, as agreed for this project.
