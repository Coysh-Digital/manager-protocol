# Manager protocol

The wire contract between the **Manager** platform and the **Manager Connector** for Craft CMS.

This package is deliberately tiny and has **no runtime dependencies** beyond PHP's own `sodium` and
`json` extensions. It runs inside privileged plugin code on customer sites, so anything it pulls in
would have to be reviewed to the same standard as the connector itself.

It exists as a separate package because the contract is shared by two repositories under different
licences: the [control plane](https://github.com/Coysh-Digital/manager) is AGPL-3.0 and the
[Craft connector](https://github.com/Coysh-Digital/craft-manager-connector) is MIT. Vendoring copies
into both guarantees they drift, and drift in a signing protocol is a security event. Keeping it here
means a protocol change is a version bump and two dependent pull requests: deliberate friction, in the
one place where surprises are least welcome.

It is MIT, which is the most permissive of the three deliberately. This is the specification of how a
site proves its identity to a control plane, and anyone should be able to read, verify or reimplement
it without asking us, including to point the connector at something else entirely.

## What is in the box

| Class | Responsibility |
|---|---|
| `Protocol` | Constants: prefixes, header names, tolerances, size caps, the capability list |
| `CanonicalRequest` | The exact bytes a connector signs, and path/query canonicalisation |
| `CanonicalResponse` | The exact bytes the platform signs, bound to the request nonce |
| `Keys` | Ed25519 keypair generation, signing and verification over libsodium |
| `Nonce` | Request nonces and single-use enrolment codes, plus their validation and hashing |
| `SchemaValidator` | Strict allowlist validation of connector payloads |
| `Sealing` | X25519 sealed boxes: handing a key to a recipient without a shared secret |
| `ArtifactStream` | Chunked authenticated encryption for backups, so nothing large is held in memory |
| `ArtifactEnvelope` | The self-describing header that makes a v2 artifact a file rather than a row |
| `KeyFingerprint` | Short, human-comparable names for public keys |
| `RecoveryProof` | The challenge and response that prove somebody holds a recovery private key |
| `Jobs` | The closed vocabulary of work a platform may ask a site to do |
| `InventorySections` | Which report sections each capability permits |

## Request signing

Every connector request carries these headers:

```
Manager-Site:              01JRZX9K2Q4M8N7P6T5V3W2Y1B
Manager-Timestamp:         1785340000
Manager-Nonce:             Zm9vYmFyYmF6cXV4MTIzNA
Manager-Connector-Version: 1.0.0
Manager-Signature:         v1=<base64 Ed25519 signature>
```

The signature covers this newline-joined canonical string:

```
MGR1
<site external id>
<connector version>
<unix timestamp>
<nonce>
<HTTP METHOD>
<canonical path>
<hex sha256 of the raw body>
```

Every field that changes the meaning of a request is in there. Alter the method, the path, the
query, the body or the timing and the signature stops verifying - there is a test per field.

The canonical path sorts query parameters, so a proxy that reorders them cannot break verification,
and an attacker cannot tamper with them either.

### What the platform must do on receipt

In this order, because each step is cheaper than the next and none of them should be reachable with
a payload that failed an earlier one:

1. Reject bodies over `Protocol::MAX_PAYLOAD_BYTES`, before parsing.
2. Require every header in `Protocol::requiredRequestHeaders()`.
3. Reject timestamps outside `Protocol::DEFAULT_TIMESTAMP_TOLERANCE`.
4. Reject a nonce that has been seen. **If the nonce store is unreachable, reject** - this is the
   one place where availability loses to correctness.
5. Look up the site and verify the signature.
6. Rate-limit by site and by source network.

An unknown site and a bad signature must return an identical response through the same code path.
Anything else tells an attacker which site identifiers exist.

TLS is still mandatory. Signing protects integrity and replay; it does nothing for confidentiality.

### Response signing

Responses carrying commands or security-sensitive configuration are signed by the platform over
`CanonicalResponse`, which **includes the request nonce**. That binding is the point: without it, a
captured response - say, one granting a capability - could be replayed at the connector against a
later request.

A connector that expects a signed response and does not get a valid one must treat the request as
failed. Never as an unsigned success.

## Enrolment codes

`Nonce::generateEnrolmentCode()` returns 256 bits of CSPRNG output behind an `mgr_enrol_` prefix, so
a leaked code is recognisable in a log or a paste.

Only `Nonce::hashEnrolmentCode()` output is ever stored. That is a plain SHA-256, and deliberately
not a password hash: the code has no dictionary to slow an attacker down to, and the pairing
endpoint has to consume it in a single indexed statement to stay atomic under concurrent requests.
Brute force is handled by entropy plus rate limiting, which is where it belongs.

## Payload schemas

`schemas/inventory.v1.json` is an allowlist of the operational metadata a connector may report. It
maps one-to-one onto the spec's data-minimisation list, and the platform documents why each field is
necessary.

`SchemaValidator` **rejects** unknown keys rather than stripping them. This is the single most
important behaviour in the package: silently dropping unrecognised fields would let a connector
widen what it collects without anyone noticing, whereas failing loudly makes drift visible the
moment it appears. Adding a field is a new schema version, not an edit.

Validation errors name the offending path and never quote its value, because those strings reach
logs and a rejected payload may be carrying exactly the key material that should not be there.

Two limits of the validator worth knowing before writing a schema against it, because both have
already caught somebody out. It implements **no `minLength` and no `minItems`** - `backup.v1.json`
carries a `"minLength": 26` that has never enforced anything - so express length as an anchored
`pattern` with an explicit quantifier. And PCRE's `$` matches *before* a trailing newline, so
`^[0-9a-f]{64}$` accepts `"…\n"`; anchor with `\z`.

## Backup artifacts

A v1 artifact was a bare `ArtifactStream`, with its key sealed to the platform. The platform could read
every backup it held, and the connector's documentation said so.

A v2 artifact is an `ArtifactEnvelope` wrapped around the same stream, with the key sealed to an
organisation's own recovery keys and to nothing else. The platform stores, verifies, serves and deletes
something it cannot open.

```
MGRBAK | major | minor | len | manifest | len | signature | ArtifactStream …
```

The manifest carries everything needed to decrypt the file **offline, with a private key and nothing
else** - that is the whole point, because a file that needs our database to describe itself has not
achieved zero-knowledge. It is signed by the site's own connector key, so whoever holds the file can
confirm which site produced it without asking the platform, which matters because the platform is the
party being checked.

The manifest travels as *bytes* everywhere, never as an object to be re-encoded. `backup.v2` carries it
base64'd for exactly that reason.

`ArtifactStream` is unchanged between the two formats, deliberately. It has the only genuine
cross-implementation byte-compatibility test in this package, and the change from v1 to v2 is about who
can obtain the key, not about how bytes are encrypted.

A v3 artifact is **the same file**. The envelope above, the signing prefix, the encryption and the
chunk size are all identical, and `FORMAT_MAJOR` is still 2 - a reader that opens a v2 artifact opens a
v3 one with no new cryptography. What changed is only what the two documents are permitted to *say*
about size: `backup.v2` hard-coded a 2 GiB maximum on `artifact_bytes`, `backup-manifest.v2` did the
same for the dump and the ciphertext, and `backup.v3`/`backup-manifest.v3` carry no maximum at all. How
large an artifact a platform will accept belongs to that platform's configuration, where an operator
can change it and a refusal can name it.

`backup.v3` also requires `artifact_crc32c` beside `artifact_sha256`. Above five gigabytes an artifact
is assembled from parts, and an object store can only verify a whole-object checksum across such an
assembly when the algorithm linearises - CRC-32C does, SHA-256 does not. It is a transport check and
never the integrity one: `artifact_sha256` remains what a customer verifies offline.

## Fixtures

`fixtures/` holds the cross-implementation contract - known inputs with their expected canonical
strings and signatures, generated from a fixed seed. Both the platform and the connector test
against these files, so a change that breaks byte-compatibility fails in CI rather than in
production. See `fixtures/README.md`.

The keypair committed there is test data derived from a fixed seed. It must never be used anywhere
real; it is committed precisely so anyone can reproduce the signatures.

## Development

```bash
composer install
composer test        # pest
composer phpstan     # level 8
```

## Security

Report vulnerabilities privately to support@managerforcraft.com. Do not open a public issue.

## Licence

**MIT.** See [LICENSE.md](LICENSE.md).

Requires PHP 8.1+ and the `sodium` and `json` extensions. Nothing else.
