# Deidentify Bundle

`deidentify` is a local-first release aid for preparing a Git project or text bundle for external sharing. It never modifies the selected source directory. It discovers possible organisational fingerprints, requires human approval before replacing them, writes a new tarball, and verifies the staged result before export.

It is not a guarantee of anonymity. Unique architecture, business logic, dependencies, or combinations of harmless facts can still identify an organisation. Treat it as one control in an approved public-release process.

## Security model

The tool reduces accidental disclosure of company, customer, project, internal-system, and infrastructure identifiers in text bundles. It assumes credential scanning and PII/DLP controls are enforced separately.

- The source root must not be a symlink; symlinked files and directories are skipped and recorded.
- Files use no-follow reads and must remain under the selected root.
- `.git`, common key files, and environment files are excluded by policy.
- Approved terms are replaced deterministically in file contents and paths; the source stays unchanged.
- Builds fail for transformed-path collisions, unsafe output paths, approved terms left in staged paths/content, or unsupported files under the default policy.
- Builds refuse to overwrite an existing archive or manifest.
- Archive owner/group/timestamp metadata is normalised. The fingerprint and replacement map never enter the archive or manifest.

## Sanctioned internal AI

An organisation-sanctioned internal AI can improve discovery. Enterprise-approved GitHub Copilot is common, but not required. Use only an AI service whose tenancy, retention, data handling, and access controls are approved by your organisation. Never send review or audit artifacts to a public or unapproved service.

The CLI does not call an AI provider. It writes bounded JSON artifacts so the provider boundary stays explicit. AI findings always import as `candidate`; only a person can mark an entry `approved`.

## Recommended public-release workflow

1. Run existing secrets and PII/DLP gates.
2. Create or update a local, access-controlled fingerprint.
3. Scan, submit the bounded review request to sanctioned internal AI, and import its candidates.
4. Human-review the fingerprint and approve only vetted entries.
5. Run `preview` and resolve unexpected changes, omissions, and collisions.
6. Generate an adversarial audit request from staged content, submit it to the sanctioned AI, and review findings.
7. Build with `--fail-on-ai-findings` for public release; resolve or explicitly dismiss open medium/high findings.
8. Independently inspect the archive and manifest, then upload as a separate deliberate action.

```bash
python -m pip install -e .

deidentify init fingerprint.json
deidentify scan /path/to/project --report scan-report.json \
  --ai-review-request internal-ai-review.json
# Submit only to sanctioned internal AI, then save its JSON response.
deidentify import-review fingerprint.json internal-ai-response.json
# Human review: set vetted entries in fingerprint.json to "approved".

deidentify preview /path/to/project fingerprint.json --output preview.json
deidentify audit-request /path/to/project fingerprint.json --output audit-request.json
# Submit audit-request.json to sanctioned internal AI and save its response.
deidentify build /path/to/project fingerprint.json output/project-deidentified.tar.gz \
  --audit-findings audit-response.json --fail-on-ai-findings \
  --mapping-vault secure/project-mapping.vault.json

# After ChatGPT returns a modified tarball, restore it only in an approved local environment.
deidentify reidentify returned-from-chatgpt.tar.gz secure/project-mapping.vault.json \
  restored-internal.tar.gz
```

`--copilot-request` remains a compatible alias for `--ai-review-request`; the request content is provider-neutral.

## Optional reidentification

By default, no reverse map is kept. Add `--mapping-vault` at build time only when you need to restore approved internal names after an external AI returns a modified archive. The CLI prompts for a passphrase and writes a separate encrypted vault using PBKDF2-HMAC-SHA256 and authenticated Fernet encryption. The vault is never included in the deidentified archive or manifest and must remain outside the source tree.

`reidentify` reads a returned tarball without extracting it, rejects symlinks, unsafe paths, non-regular members, binary/non-UTF-8/unsupported files, and path collisions, then creates a fresh local tarball with normalised metadata. It never modifies the returned archive.

Reidentification restores the approved **canonical** value for each token. Because deidentification intentionally maps several spelling/case variants to the same token, it cannot reconstruct every original spelling byte-for-byte. Keep the vault and its passphrase as sensitive credentials; losing either makes reidentification impossible.

## Discovery and review

Static discovery ranks candidates from paths and file contents, retaining whether evidence is path- or content-based. It checks domains, URLs, email addresses/domains, IP addresses, UUIDs, AWS ARNs, Azure resource identifiers, proper names, PascalCase, lowerCamelCase, snake_case, uppercase identifiers, and kebab-case identifiers. Candidates are not declarations of sensitivity.

The AI review artifact includes a candidate inventory and at most 200 short source snippets. The bounded context helps discover aliases, codenames, naming conventions, and business context without sending the entire repository in one request.

Fingerprint states are:

- `candidate`: scanner or AI proposal; never transformed.
- `approved`: human-confirmed identifier; transformed in preview/build.
- `ignored`: reviewed as generic or safe.

Keep the fingerprint outside the source tree where possible and protect it as sensitive organisational data.

## AI response formats

Discovery responses are JSON with `entries`. Each entry needs `canonical`, `category`, `variants`, `confidence` (`low`, `medium`, or `high`), `rationale`, and `evidence` with path/line where available.

Adversarial audit responses have `findings`, each with `clue`, `category`, `path`, `line`, `explanation`, `confidence`, and `status` (`open` or `dismissed`). `--fail-on-ai-findings` blocks on open medium/high findings.

## Unsupported-file policy, preview, and verification

Only recognised UTF-8 text files are transformed. Unknown extensions, binaries, malformed UTF-8, and files over 2 MB fail a build by default. This avoids silently creating an incomplete archive. Use `--unsupported-policy exclude` only after review; every omission and reason appears in the manifest and CLI summary. Archives, images, PDFs, generated artifacts, and other unknown files are not inspected by this version.

`preview` writes a JSON record of changed paths/content, replacement counts, responsible approved entries, output count, and omissions. It never writes to source or produces an archive.

Build uses longer variants first, case-insensitively, for contents and every path component. It independently scans staged paths and text after transformation; any residual approved variant blocks export.

## License

This project is licensed under the [MIT License](LICENSE). Its canonical SPDX identifier is [`MIT`](https://spdx.org/licenses/MIT.html).
