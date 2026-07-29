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
