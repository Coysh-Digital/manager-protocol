# Fixtures

These files are the cross-implementation contract. The platform and the connector both run their
tests against them, so a change to either side that breaks byte-compatibility fails in CI rather
than in production.

## `signing.json`

Known inputs and their expected canonical strings and signatures, produced from a **fixed seed**.
The keypair in this file is test data and must never be used anywhere real — it is committed
precisely so that anyone can reproduce the signatures.

If a change to `CanonicalRequest` or `CanonicalResponse` makes these signatures stop verifying, that
is a wire-format break: bump the protocol version rather than regenerating the fixture.

## `inventory.v1/`

| File | Expectation |
|---|---|
| `valid.json` | Accepted. A realistic report from a healthy Craft 5 production site. |
| `unknown-field.json` | **Rejected.** Carries `site_admin_email`, which the schema does not permit. Models a connector that has started collecting more than was agreed — the failure is the point. |
| `forbidden-content.json` | **Rejected.** Carries entries, user records, password hashes, database credentials and environment values. Every one of these is named in the spec's data-minimisation list as something that must never appear. |

## `updates.v1/`

| File | Expectation |
|---|---|
| `valid.json` | Accepted. A site two patch releases behind, one of them a security release. |
| `forbidden-content.json` | **Rejected.** Carries release notes, a download URL and licence keys. The platform needs to know *that* an update exists and whether it is security-critical; an advisory body pasted into a dashboard is a description of an unpatched vulnerability on a named site. |

## `backup.v1/`, `system.v1/`, `logins.v1/`

The same pattern: `valid.json` is accepted, `forbidden-content.json` is rejected. What each forbidden
file carries is listed in the schema's own description — a dump path and table names for `backup.v1`,
filesystem paths and visitor addresses for `system.v1`, usernames and source addresses for `logins.v1`.

## `envelope.v2/`

The reference artifact, and the most load-bearing fixture here.

| File | What it is |
|---|---|
| `artifact.bin` | A complete v2 backup artifact, 1,892 bytes: envelope, manifest, signature and an encrypted stream containing a three-line "dump". |
| `reference.json` | Every key needed to open it, plus the values a reader should arrive at. |

Three implementations parse these bytes — the connector that writes them, the platform that stores
them, and `manager-restore` that decrypts them — so this file is where they find out they disagree.

**Every key in `reference.json` is derived from a printable fixed seed** (`manager-recovery-fixture-a`
padded with zeroes, and so on). They are committed so anybody can reproduce the artifact, and they are
test data. The seeds are deliberately readable so a key committed to a public repository is obviously
not a real one at a glance.

The test that matters most opens `artifact.bin` with a private key and nothing else — no platform, no
database, no network — and gets the original dump back. That is the customer's position after a
restore, and if it ever stops working, "zero-knowledge" is a slogan rather than a property.

`manifest_signature`, `manifest_sha256` and `body_offset` are pinned in the test. If a change to
`ArtifactEnvelope` makes them stop matching, that is a wire-format break: bump the protocol version
rather than regenerating the fixture. The same rule as `signing.json`.

## `backup.v2/` and `backup-manifest.v2/`

| File | Expectation |
|---|---|
| `backup.v2/valid.json` | Accepted. The declaration for `envelope.v2/artifact.bin`, so the two cannot drift apart. |
| `backup.v2/unknown-field.json` | **Rejected.** Carries `storage_endpoint`, which models the specific mistake worth catching in this format: a destination arriving as data. |
| `backup.v2/forbidden-content.json` | **Rejected.** The v1 list — credentials, DSN, dump path, table names, sample rows. |
| `backup-manifest.v2/valid.json` | Accepted, and decodes to exactly the manifest embedded in `artifact.bin`. |
| `backup-manifest.v2/unknown-field.json` | **Rejected.** Carries `database_host`. |
| `backup-manifest.v2/forbidden-content.json` | **Rejected.** Carries `secret_key` and `private_key` inside a recipient entry, alongside the usual list. Those two are the interesting ones: a recipient already holds a wrapped key and a public key, so a secret key beside them is exactly the field somebody would add "for convenience", and it would defeat the entire arrangement. |

Note what is *absent* from `backup.v2/valid.json`: there is no `sealed_key`. v1 carried one, sealed to
the platform's own box key, and the platform opened it on arrival. Its absence is the whole difference
between the two formats, and there is a test that asserts it rather than leaving it to be noticed.

## `backup-progress.v1/`

| File | Expectation |
|---|---|
| `valid.json` | Accepted. A job identifier, a stage, a timestamp. |
| `forbidden-content.json` | **Rejected.** Carries a dump path, a running byte count, the table currently being written and a DSN. A progress report is where those look harmless — a table name is a description of the site's schema, and a byte count as the dump grows leaks the size of the database in real time. |
