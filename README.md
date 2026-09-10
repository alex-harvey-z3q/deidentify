# Deidentify Bundle

`deidentify` is a local-first release aid for preparing a Git project or text bundle for external sharing. It never modifies the selected source directory. It discovers possible organisational fingerprints, uses an organisation-sanctioned internal AI to select replacements, writes a new tarball, and verifies the staged result before export.

It is not a guarantee of anonymity. Unique architecture, business logic, dependencies, or combinations of harmless facts can still identify an organisation. Treat it as one control in an approved public-release process.

## Security model

The tool reduces accidental disclosure of company, customer, project, internal-system, and infrastructure identifiers in text bundles. It assumes credential scanning and PII/DLP controls are enforced separately.

- The source root must not be a symlink; symlinked files and directories are skipped and recorded.
- Files use no-follow reads and must remain under the selected root.
- `.git`, common key files, and environment files are excluded by policy.
- Approved terms are replaced deterministically as portable tokens such as `__PROJECT_001__` in file contents and paths; the source stays unchanged.
- Builds fail for transformed-path collisions, unsafe output paths, approved terms left in staged paths/content, or unsupported files under the default policy.
- Builds refuse to overwrite an existing archive or manifest.
- Archive owner/group/timestamp metadata is normalised. The fingerprint and replacement map never enter the archive or manifest.
- Release artifacts such as reports, AI request/response files, previews, audits, human reviews, vaults, archives, and manifests must live outside the selected source tree. `init` deliberately permits a fingerprint anywhere for a simple first-run experience, but keeping it outside the source tree is strongly recommended.

## Sanctioned internal AI

An organisation-sanctioned internal AI can improve discovery. Enterprise-approved GitHub Copilot is common, but not required. Use only an AI service whose tenancy, retention, data handling, and access controls are approved by your organisation. Never send review or audit artifacts to a public or unapproved service.

The CLI does not call an AI provider. It writes bounded JSON artifacts so the provider boundary stays explicit. In the streamlined workflow below, choosing `package` explicitly accepts every entry added or updated by that internal-AI response. This is deliberately less conservative than the advanced commands: the internal AI is the decision-maker for that release, and unrelated candidate entries remain untouched.

## Streamlined workflow

This is the intended default for teams that already run secret/PII/DLP gates and accept a pragmatic rather than perfect result. It has two local commands and one internal-AI hand-off:

```bash
python -m pip install -e .

deidentify prepare /path/to/project --workspace /secure/deidentify-work
# Send only /secure/deidentify-work/internal-ai-review-request.json to the sanctioned internal AI.
# Save its JSON response as /secure/deidentify-work/internal-ai-review-response.json.
deidentify package /path/to/project --workspace /secure/deidentify-work

# After ChatGPT returns a modified tarball, restore it only in an approved local environment.
deidentify reidentify returned-from-chatgpt.tar.gz /secure/deidentify-work/project-deidentified.tar.gz.mapping.vault.json \
  restored-internal.tar.gz
```

`prepare` creates or reuses `fingerprint.json` in the workspace, scans the source, and writes the bounded review request. `package` imports the saved response, approves exactly the entries touched by that response, then builds an archive and an encrypted mapping vault. It prompts for the vault passphrase. Its default `--unsupported-policy exclude` omits non-text files rather than blocking the bundle; omissions are recorded in the manifest. Use `--unsupported-policy reject` when completeness matters more than convenience.

The workspace is sensitive: it holds the accumulated organisation fingerprint, the AI review artifacts, and the encrypted vault. Keep it outside the repository and in an access-controlled location. `package --no-mapping-vault` is available only when reidentification is not needed.

`--copilot-request` remains a compatible alias for `--ai-review-request`; the request content is provider-neutral.

## Advanced controls

The individual `init`, `scan`, `import-review`, `approve`, `preview`, `audit-request`, `audit-review-template`, and `build` commands remain available for a more conservative release process. They allow separate human approval, preview, and adversarial audit gates when required.

## Optional reidentification

By default, no reverse map is kept. Add `--mapping-vault` at build time only when you need to restore approved internal names after an external AI returns a modified archive. The CLI prompts for a passphrase and writes a separate encrypted vault using PBKDF2-HMAC-SHA256 and authenticated Fernet encryption. The vault records the originating transformed-tree digest as provenance, is never included in the deidentified archive or manifest, and must remain outside the source tree.

`reidentify` reads a returned tarball without extracting it, rejects symlinks, unsafe paths, non-regular members, binary or non-UTF-8 files, and path collisions, then creates a fresh local tarball with normalised metadata. It accepts any UTF-8 filename because a token can replace an entire filename and remove its original extension. It never modifies the returned archive.

Reidentification restores the approved **canonical** value for each token. Because deidentification intentionally maps several spelling/case variants to the same token, it cannot reconstruct every original spelling byte-for-byte. Keep the vault and its passphrase as sensitive credentials; losing either makes reidentification impossible.

## Discovery and review

Static discovery ranks candidates from paths and file contents, retaining whether evidence is path- or content-based. It checks domains, URLs, email addresses/domains, IP addresses, UUIDs, AWS ARNs, Azure resource identifiers, proper names, PascalCase, lowerCamelCase, snake_case, uppercase identifiers, and kebab-case identifiers. Candidates are not declarations of sensitivity.

The AI review artifact includes a candidate inventory and at most 200 short source snippets. The bounded context helps discover aliases, codenames, naming conventions, and business context without sending the entire repository in one request.

Fingerprint states are:

- `candidate`: scanner or AI proposal; never transformed.
- `approved`: identifier accepted for transformation; transformed in preview/build.
- `ignored`: reviewed as generic or safe.

Keep the fingerprint outside the source tree where possible and protect it as sensitive organisational data.

`package` and `import-review --approve-all` are explicit user decisions to accept all candidates touched by that AI review. They never honour an AI-provided status field on its own, and they do not change unrelated existing candidates. `approve --all` is the separate explicit action for all current candidates in a fingerprint.

## Audit binding and AI response formats

Discovery responses are JSON with `entries`. Each entry needs `canonical`, `category`, `variants`, `confidence` (`low`, `medium`, or `high`), `rationale`, and `evidence` with path/line where available.

Every adversarial audit request includes a deterministic `tree_digest` in the form `sha256:<hex>`. It is calculated from sorted transformed paths and exact transformed file bytes. Audit requests are split into deterministic batches; each has a `batch_id` and `batch_digest`.

The raw AI response must echo the exact `tree_digest` and return every required batch with its exact `batch_id` and `batch_digest`. Raw findings have `clue`, `category`, `path`, `line`, `explanation`, and `confidence`. Any AI-provided `status` is ignored and every raw finding is normalised to `open`.

`audit-review-template` creates a separate human-review artifact. A human can dismiss a known finding only by adding its `finding_id`, `status: "dismissed"`, and a non-empty reason. Both the audit response and human-review artifact must apply to the current `tree_digest`; otherwise the build fails closed. `--fail-on-ai-findings` blocks on remaining open medium/high findings.

## Unsupported-file policy, preview, and verification

Only recognised UTF-8 text files are transformed. Unknown extensions, binaries, malformed UTF-8, and files over 2 MB fail a build by default. This avoids silently creating an incomplete archive. Use `--unsupported-policy exclude` only after review; every omission and reason appears in the manifest and CLI summary. Archives, images, PDFs, generated artifacts, and other unknown files are not inspected by this version.

`preview` writes a JSON record of changed paths/content, replacement counts, responsible approved entries, output count, omissions, the transformed-tree digest, and short-variant risks. It never writes to source or produces an archive.

Build uses longer variants first, case-insensitively, for contents and every path component. It independently scans staged paths and text after transformation; any residual approved variant blocks export. Path validation and collision checks use Windows-compatible semantics, including case folding and trailing dot/space handling.

Approved variants shorter than four characters are shown in preview with their affected-file and occurrence counts. They are transformed like every other approved variant; use this information to assess the impact of intentionally broad replacements.

## License

This project is licensed under the [MIT License](LICENSE). Its canonical SPDX identifier is [`MIT`](https://spdx.org/licenses/MIT.html).
