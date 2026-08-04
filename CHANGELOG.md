# Changelog

This package is the wire contract between the Manager platform and the connectors that report to it.
A change here is a change to what a site may send, so every entry says what was added and - more
usefully - what was deliberately left out of it.

## 1.6.0

`system.v2`. A volume now says where its files are, and - when it could not be measured - which of
the several different reasons applied.

### What was wrong

`measured: false` meant three unrelated things: the files are on remote storage and walking them
would mean an API call per directory billed to the site; the walk started and ran out of the
connector's time budget, so the figures are a floor; or the path resolved to nothing the process
could open. A screen receiving that had no way to tell them apart, and they want three different
responses - nothing at all, a larger budget, and somebody fixing a misconfiguration.

The second half is arithmetic rather than presentation. A remote volume's bytes are not on the
server's disk, so a report that cannot say which volumes are remote cannot say what the disk figures
beside them do and do not include.

### What changed

- **`location`** - `local` or `remote`, per volume. Optional: a connector that cannot tell omits it
  rather than guessing.
- **`unmeasured_reason`** - `remote`, `timeout` or `unreadable`, and meaningful only where `measured`
  is false. Also optional.

`v1` is untouched and still refuses everything it refused, so a v1 connector and a v2 platform stay
compatible in both directions.

### What was deliberately left out

**The adapter's name, and everything that travels with it.** `location` is two values, and the
tempting third is `s3` - which reads as more useful and is the first step of a slide, because a
provider name invites a bucket beside it, then a region, then an endpoint. Those identify a
customer's infrastructure; `local` or `remote` says which of two shapes it has, which is all a
screen needs to know whether the bytes count towards a disk. `v1`'s `handle` description said "not
its path, and not its filesystem type", and only the second half of that has been relaxed. There is
a must-fail fixture carrying a bucket, a region, an endpoint and an adapter class, and a test that
the enum refuses `s3`.

**A per-directory breakdown of what the walk did reach.** A timed-out volume reports the total it
got to and that the total is partial. Saying *which* subtrees it managed would be a directory
listing arriving one timeout at a time.

## 1.5.0

`backup.v3` and `backup-manifest.v3`. An artifact may now be larger than two gigabytes, and the
decision about how much larger stops being the protocol's.

### What was wrong

`backup.v2` declared `artifact_bytes` with `"maximum": 2147483648` and described it as "the platform's
artifact limit". It was not the platform's limit. It was this package's, written into a published
schema where no operator could raise it and no hosted edition could lift it, and the description
saying otherwise is how it went unnoticed.

It refused four consecutive nightly backups on a live site whose database had grown past it. The
hosted edition had already decided that a customer past their allowance should be **billed for the
space rather than refused the backup** - it binds a seam that tells the connector "no limit" - and
then the wire contract refused anyway, after the site had dumped and encrypted the whole database.
`backup-manifest.v2` carried the same 2 GiB maximum on `plaintext_bytes` and `ciphertext_bytes`, so a
declaration let through on size would have been refused a step later on the same grounds.

### What changed

- **`backup.v3`** - `artifact_bytes` keeps its floor of 128 and has no maximum. What an individual
  platform accepts is that platform's configuration, enforced there, and named in the refusal so an
  operator can change it.
- **`backup-manifest.v3`** - `plaintext_bytes` and `ciphertext_bytes` likewise keep `minimum: 1` and
  lose their maxima.
- **`artifact_crc32c`** is added to the declaration, and required. Above five gigabytes an artifact
  cannot be uploaded in one request, and an object store can only confirm a whole-object checksum
  across a multipart assembly if the algorithm linearises. SHA-256 does not; CRC-32C does.
- **`Protocol::MIN_ARTIFACT_BYTES`, `SINGLE_PUT_MAX_BYTES` and `ARTIFACT_PART_BYTES`** are added.
  `MAX_ARTIFACT_BYTES` keeps its name and its value and becomes a *default* - what a platform adopts
  when its operator has chosen nothing. Its docblock says so; nothing that reads it needs to change.

### What was deliberately left out

- **No part locations.** The declaration gained a checksum and nothing else. There is no host, no
  bucket, no endpoint, no region, no upload id and no array of part URLs, and `BackupV3SchemaTest`
  asserts each of those names is absent rather than merely unused. A multipart upload is the first
  time an artifact travels as more than one request, which makes it exactly the change during which a
  destination would arrive as data "for convenience". The connector's build check already refuses a
  destination read from anything the platform sends; this keeps there being nothing to read.
- **No per-part checksums.** They were the alternative to CRC-32C and would have meant the platform
  confirming N hashes a connector declared instead of one whole-file value. Full-object mode keeps
  the binding whole-file.
- **No new envelope.** `FORMAT_MAJOR` is still 2 and `MANIFEST_SIGNING_PREFIX` is still
  `MGRBAK-MANIFEST-v2\n`. A v3 artifact differs from a v2 one only in which numbers its manifest is
  permitted to carry, so a reader needs a second schema name and no second verification path - and
  every artifact ever written stays verifiable by the rule it was written under.
- **No looser chunking.** `chunk_bytes` is still pinned to 1 MiB. A larger artifact means more chunks,
  not larger ones, so nothing about how a reader frames the stream moved.
- **Nothing removed from v2.** Both v2 schemas are untouched and still refuse exactly what they always
  refused; there are tests asserting it in both directions. A connector still sending `backup.v2` gets
  v2's answer, including its ceiling. `signing.json` and `envelope.v2/artifact.bin` are byte-identical.

### On the CRC, honestly

On the multipart path an object store enforces a CRC-32C rather than a SHA-256. Against corruption in
transit the two are equivalent, which is the job this checksum does. Against a connector deliberately
sending other bytes, CRC-32C is forgeable and SHA-256 is not - but that connector chose the plaintext
in the first place, and a platform holding a v2 or v3 artifact cannot read it either way. What binds
these bytes to a site has never been the transport checksum: it is the Ed25519 signature over the
manifest, which the customer verifies offline with `manager-restore`. `artifact_sha256` stays in the
declaration, stays covered by the request signature, and stays what restore checks.

## 1.4.0

The PHP floor drops from 8.2 to 8.1. No code changed, and nothing on the wire moved.

This exists to let the connector support Craft 4. Craft 4 runs on PHP 8.0.2+, and the sites still on
Craft 4 are disproportionately the ones still on an older PHP - a connector that required 8.2 would
have reached mainly the sites that could have upgraded to Craft 5 anyway.

### What changed

`composer.json` now requires `php: >=8.1`. That is the whole of it. The source already parsed on 8.1:
the newest construct in the package is a `readonly` promoted constructor property, which is 8.1, and
there was no readonly class, no standalone `false`/`null` return type and no constant in a trait.

### Why 8.1 and not 8.0.2

8.0.2 is Craft 4's own floor and would have reached every Craft 4 site. It was not free: `readonly`
appears on thirteen promoted properties across `CanonicalRequest`, `CanonicalResponse` and
`SchemaValidator`, and those are precisely the objects a signature is computed over. Trading their
immutability for the sites still on 8.0 was not worth it.

### What holds the floor

`phpstan.neon` now sets `phpVersion: {min: 80100, max: 80400}`, so the source is analysed across the
whole supported range rather than only on whatever the runner has.

That is load-bearing, because the test matrix does **not** cover 8.1 and cannot: Pest 3 requires
^8.2.0, so `composer install` will not resolve there. Without the PHPStan range this release would be
a claim about 8.1 with nothing behind it - which is the failure mode worth naming, since it would
present as an install error on a customer's site rather than as a red build here.

## 1.3.0

Release notes cross the wire, and where they may be stored is the whole of the change.

Additive. `updates.v1.json` is untouched and still rejects everything it always rejected, so a 1.2
connector and a 1.3 platform remain compatible in both directions. Nothing else in the package moved:
no new capability, no signing change, and the fixtures verify byte for byte.

### What changed

`updates.v2.json` is `updates.v1.json` plus one field. A plugin entry may carry `releases[]` - the
versions between the one a site is running and the one it could run, each with a `version` and
optionally the `notes` the plugin published, a `critical` flag and a `date`. It is sent only for a
plugin that actually has an update available, and it is bounded: ten releases per plugin, four
thousand characters per note.

### Why this is not the thing v1 refused

v1's description said, flatly, "no release notes, no changelog bodies". That was aimed at a real
problem and the problem has not gone away - but it was aimed slightly wrong.

The text itself is public. The Craft Plugin Store serves it to anyone who asks, and the site already
holds a copy, which is how the connector can send it without making a single outbound request. What
was never safe was the *association*: a row that says "this named site is three versions behind these
fixes" is a map of an exploitable installation, and that is worth refusing whether the notes arrive
over the wire or are fetched afterwards.

A schema cannot express where a receiver puts what it is given, so v2 carries the notes and states
the obligation in its own description: store them against a plugin and a version, never against a
site. The platform holds up that end - its `plugin_release_notes` table has no site column and an
invariant test asserts the update report itself is stripped before it is written. A receiver that
stores them per site has reintroduced exactly the problem v1 refused, and nothing here will stop it.

The fields v1 refused for a simpler reason are still refused: no download URLs, no licence keys.
`fixtures/updates.v1/forbidden-content.json` is unchanged and still must fail, and there is now a v2
fixture beside it that must fail for the same reasons.

## 1.2.0

The backup format that the platform cannot read.

Additive throughout. `backup.v1.json` is untouched, `ArtifactStream` is untouched, and the signing
fixtures still verify byte for byte, so a 1.1 connector and a 1.2 platform remain compatible in both
directions. **No capability was added** - `backups:create` still governs, and a site that has not
granted it is no more reachable than before.

### What changed, and why it is a version rather than a patch

Under `backup.v1` a connector sealed the artifact key to the *platform's* public key, and the platform
opened it on arrival. That was honest - the connector's documentation said in as many words that it
was not end-to-end encryption - but it meant anybody holding the platform's backup secret key and its
storage could read every backup it held.

Under `backup.v2` the key is sealed to an organisation's own recovery keys and to nothing else. The
platform stores, verifies, serves and deletes something it cannot open.

That is only true if the file can be opened *without* the platform, so v2 artifacts are self-describing
rather than being bytes that mean nothing without a database row beside them.

### `backup.v2` - the declaration

`sealed_key` is gone, and its absence is the whole change. What replaces it is a manifest, carried as
base64 of the exact bytes embedded in the artifact file, with its SHA-256 and an Ed25519 signature by
the site's own connector key.

The manifest travels as **bytes, not as an object**. Re-serialising a decoded document and expecting a
signature to survive is the canonicalisation trap that breaks verification a year later, on a different
PHP minor, over how a slash or a float was rendered. Nothing between the connector and a customer's
laptop re-encodes it.

Also new: `artifact_sha256` and `artifact_bytes` cover the whole file - envelope, manifest, signature
and stream - where v1's `ciphertext_sha256` covered the stream alone. And `upload_mode`, which is
*reported* rather than instructed: it records whether the bytes went to the paired platform or to a
short-lived grant, and nothing the platform sends names a host.

### `backup-manifest.v2` - what travels inside the file

Everything needed to decrypt offline with a private key and nothing else: scheme, chunk size, stream
header, integrity hashes, and one wrapped copy of the data-encryption key per recovery key that was
active when the backup was taken.

Absent by design: anything describing the data inside. Somebody holding only a manifest learns that a
database of a certain size was taken from a certain site at a certain time, and which keys open it.
The `forbidden-content.json` fixture carries `secret_key` and `private_key` inside a recipient entry
specifically to prove those are refused - a recipient already holds a wrapped key and a public key, so
a secret key beside them is exactly the field somebody adds for convenience, and it would defeat the
entire arrangement.

`recipients` is capped at `Protocol::MAX_BACKUP_RECIPIENTS` (8), because every entry is another copy of
the key that opens the backup. There is no minimum, and the schema says so: this validator implements
no `minItems`, so "at least one recipient" is a check in the platform and the connector. Claiming it
here would repeat the `minLength` mistake described under 1.1.0.

### `backup-progress.v1`

A job identifier, one stage from a closed list, and a timestamp. Nothing else.

The temptation with a progress report is to attach what is being worked on, and every candidate is a
description of the site's data wearing a harmless heading: a table name describes the schema, a path
describes the filesystem, a running byte count leaks the size of the database as it grows. Only `dump`
is sent today - it is the longest phase and the only stage whose information is not derivable from a
later report. `encrypt` and `upload` are reserved so a connector can begin sending them without a
platform change.

### `ArtifactEnvelope`

Magic, two version bytes, a length-prefixed manifest, a length-prefixed signature, then the
`ArtifactStream` output unchanged. Length-prefixed rather than delimiter-scanned, because a reader has
to find where the stream begins without parsing JSON.

Telling v1 from v2 needs no metadata: a v1 artifact opens with a 24-byte random secret-stream header,
so the chance of one beginning with `MGRBAK` is 2^-48.

The manifest signature is domain-separated with its own prefix, alongside `MGR1` and `MGR1-RESPONSE`,
so a manifest signature can never be replayed as a request signature.

**The manifest is deliberately not bound into the AEAD as additional data**, and the reason is worth
recording rather than leaving to be rediscovered. A manifest lifted from one artifact and pasted onto
another yields a key that does not open the stream it now claims to describe, and `plaintext_sha256` is
checked after decryption. What that leaves is *rollback* - serving a genuine earlier artifact with its
own genuine manifest - and AEAD binding would not help against it either. The controls for that are the
signed `sequence` and `taken_at` fields, and somebody looking. Do not let the format be described as
preventing something it does not.

### `KeyFingerprint`

Short names for public keys, because a fingerprint is the one thing in this system a person is expected
to compare by eye.

SHA-256 over a domain string concatenated with the raw key, truncated to 15 bytes, rendered as Crockford
base32 in six groups of four: `MGRK-4F3A-9C2B-7D18-E605-2A9F-33C1`.

- **15 bytes** is 120 bits is exactly 24 base32 characters, so there is no ragged final group. The
  property relied on is second preimage resistance at 2^120; collision resistance at 2^60 is not what
  protects anything, because a fingerprint is only ever compared against one the customer already holds.
- **Crockford** excludes I, L, O and U, so there is no 1/I or 0/O ambiguity when somebody reads one
  aloud or retypes it into a configuration file. `normalise()` applies Crockford's decoding rules; U is
  rejected rather than aliased, so a U is a genuine mistake rather than a near miss.
- **Domain separation** means a site's Ed25519 key and an organisation's X25519 key cannot fingerprint
  alike even from identical bytes, and the `MGRS`/`MGRK` prefixes stop the two being cross-compared.
- **One canonical form everywhere** - wire, database, screen, config file. Not hex in one place and
  base32 in another, which is where comparison bugs live.

### `RecoveryProof`

The challenge and response that stop an unusable recovery key being enrolled.

Almost nothing can be checked about a submitted X25519 public key - any 32 bytes is a valid one - so a
customer can enrol a key from a laptop they have since wiped, take backups happily for a year, and find
out on the one night it matters. A key is therefore not usable until somebody has demonstrated they
hold the other half.

The platform seals 32 random bytes to the candidate key and stores only the hash of the expected
*response*; the operator opens it offline and reads back a short code. The response is a truncated hash
of the challenge rather than the challenge itself, so the platform never stores anything that would let
somebody else answer, and a response seen in transit reveals nothing about what was sealed.

The response is rendered in the same prefix-and-groups form as a fingerprint, under `MGRP` - copying a
short code from a terminal into a browser is the same task as comparing a fingerprint, and it should not
come with a second set of rules.

The real value is procedural rather than cryptographic: enrolling a key becomes a restore rehearsal,
which is the only check that reliably catches a key nobody can actually use.

### `Sealing::isUsableBoxPublicKey()`

Rejects small-order Curve25519 points, which would produce a sealed box anyone could open.

Stated plainly because it would otherwise read as a stronger claim than it is: **libsodium already
refuses**, and there is a test asserting that rather than assuming it. What this method buys is *when*
the refusal happens - a recovery key entered by hand is refused next to the field it was typed into,
rather than on the night a site has already dumped its database to disk and cannot seal the key.

The widely circulated list of "twelve small-order points" includes five non-canonical encodings with
the high bit set. RFC 7748 requires that bit to be masked, so those reduce to ordinary field elements
and are neither refused nor dangerous. The seven canonical ones are rejected and are what matters.

### `SchemaValidator` schema names may now contain hyphens

`~^[a-z0-9]+(-[a-z0-9]+)*\.v[0-9]+\z~`, so `backup-manifest.v2` can be named for what it is rather than
for a namespace it does not have. The property the check exists for is unchanged: no slash, no dot
beyond the version separator, so there is still no path to traverse with.

Two smaller notes on the validator, both of which v2 works around rather than changes:

- **`$` is not `\z` in PCRE.** `$` matches before a trailing newline, so `^[0-9a-f]{64}$` accepts
  `"…\n"`. The v1 schemas have always had this; it fails safe there because such a value then fails
  `hash_equals`. Every v2 pattern is anchored with `\z`. The `D` modifier was deliberately *not* added
  to the validator, because that would change how v1 documents validate.
- **There is still no `minLength` and no `minItems`.** v2 expresses every length as an anchored pattern
  with an explicit quantifier instead - including `job_id`, where `backup.v1.json`'s `"minLength": 26`
  has never enforced anything.

## 1.1.0

Two new report schemas and two new capabilities. Both schemas are additive: nothing existing changed
shape, so a 1.0 connector and a 1.1 platform remain compatible in both directions.

### `system.v1` - disk, PHP limits, response timings

Governed by the new `runtime:read` capability.

Permits byte and file counts per asset volume (by handle), free and total disk space, PHP's numeric
limits and opcache state, and summary statistics for how long the site took to build its own
responses.

Absent by design, and enforced by `additionalProperties: false` rather than by anybody's good
intentions: filesystem paths, file names, directory listings, `phpinfo()` output, ini paths, the list
of loaded extensions, and any configuration value that would name the host. A volume carries a
`measured` boolean so that "we could not walk this" stays distinguishable from "this is empty".

The response section measures **server render time, not time to first byte**. A connector times its
own site from inside the PHP process, so no DNS, TLS, queueing or network is included. The field
names say `_ms` and the description says what was measured, because a platform that labelled this
"TTFB" would be publishing a number that is wrong in a direction that flatters.

### `logins.v1` - failed control-panel sign-ins

Governed by the new `logins:read` capability.

Permits four integers and one timestamp: attempts, accounts affected, accounts locked out, and how
many of the affected accounts are administrators.

Absent by design: usernames, email addresses, user ids, source addresses, and any per-attempt record.
This is the schema doing the work that a policy cannot - a connector that started sending usernames,
through a well-meaning change or a compromised one, is refused at the door rather than having them
stripped and stored anyway.

The window is bounded (`maxItems`-style, 1 to 720 hours) because an unbounded one would make every
count monotonic and therefore meaningless.

### Capabilities

`Protocol::capabilities()` gains `runtime:read` and `logins:read`; both are read-only and appear in
`autoGrantableCapabilities()`. Neither is added to the pairing defaults - a newly paired site still
receives `inventory:read` and nothing else.

Deliberately **not** folded into `system:read`. Measuring disk means walking a directory tree and
timing responses means observing traffic; both are a different kind of collection from reading a
version number, and widening an existing grant to cover them would have had every site that had
already granted `system:read` start doing both without anybody deciding to.

## 1.0.1

- Initial public release of the wire contract: `inventory.v1`, `updates.v1`, `backup.v1`, the request
  signing scheme, the job vocabulary and the capability registry.
