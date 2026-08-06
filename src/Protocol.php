<?php

/**
 * Manager protocol.
 *
 * @link      https://coysh.digital
 * @copyright Copyright (c) Coysh Digital
 */

declare(strict_types=1);

namespace coyshdigital\managerprotocol;

/**
 * Protocol-wide constants.
 *
 * Both the platform and the connector read these, so a change here is a wire-format change.
 * Bump {@see Protocol::VERSION} and cut a release rather than editing values in place.
 */
final class Protocol
{
    /**
     * @var string Package version. Independent of the platform and connector versions.
     */
    public const VERSION = '1.7.1';

    /**
     * @var string Prefix on the canonical string a connector signs.
     */
    public const REQUEST_PREFIX = 'MGR1';

    /**
     * @var string Prefix on the canonical string the platform signs.
     */
    public const RESPONSE_PREFIX = 'MGR1-RESPONSE';

    /**
     * @var int Seconds either side of the platform clock that a request timestamp may fall.
     *
     * Deliberately tight. Widening this widens the replay window that the nonce store has to
     * remember, so the two settings move together.
     */
    public const DEFAULT_TIMESTAMP_TOLERANCE = 120;

    /**
     * @var int Largest connector payload the platform will read, in bytes.
     *
     * Enforced before any parsing so an oversized body cannot be used to exhaust memory.
     */
    public const MAX_PAYLOAD_BYTES = 262144;

    /**
     * @var int The artifact ceiling a platform adopts when its operator has not chosen one, in bytes.
     *
     * A backup does not travel as a payload - it is streamed, on its own route, and the ordinary
     * payload cap would refuse it before it started. This is the separate ceiling for that route.
     *
     * A default, not a limit, and the distinction is the whole of what changed in 1.5.0. The number
     * is the same one `backup.v2` hard-coded into its `artifact_bytes` maximum, where it stopped
     * being anybody's decision: an operator could not raise it, and a hosted edition that owns and
     * bills for the storage could not lift it. It refused live backups for four nights on a site
     * whose database had simply grown. `backup.v3` carries no maximum, so the ceiling is now
     * wherever the platform configures it - and a platform that configures nothing lands here, which
     * is the right place for a self-hosted installation writing to a disk its own operator owns.
     *
     * Still a policy statement rather than a technical one. An artifact larger than this is a site
     * whose backup strategy is worth a conversation; it is no longer a site the protocol refuses to
     * describe.
     */
    public const MAX_ARTIFACT_BYTES = 2147483648;

    /**
     * @var int Smallest artifact that could exist, in bytes.
     *
     * The envelope, a minimal manifest and a signature, with an empty stream after them. Named here
     * so `backup.v3`'s floor has a source rather than being a literal repeated in a schema.
     */
    public const MIN_ARTIFACT_BYTES = 128;

    /**
     * @var int Largest artifact an object store will accept in a single request, in bytes.
     *
     * Not a protocol decision - this is S3's documented limit for one PUT, and every store worth
     * pointing at has adopted the same number. It lives here because both sides need to agree on
     * when an upload changes shape: below it one request carries the file, above it the file is
     * assembled from parts and the whole-object checksum has to be one that linearises.
     */
    public const SINGLE_PUT_MAX_BYTES = 5368709120;

    /**
     * @var int Bytes per part when an artifact is uploaded in more than one request.
     *
     * 256 MiB puts a 20 GB artifact in eighty parts and a 5 GB one in twenty, comfortably inside the
     * ten thousand parts a store permits, while keeping a failed part cheap to retry. A platform may
     * serve a different size; this is what it uses when it has not been told otherwise.
     *
     * Unrelated to {@see self::ARTIFACT_CHUNK_BYTES}, which frames the encrypted stream and cannot
     * move. This one only decides how the finished file is cut up for transport, so changing it
     * changes nothing about whether an existing artifact can be read.
     */
    public const ARTIFACT_PART_BYTES = 268435456;

    /**
     * @var int Bytes per chunk when encrypting or decrypting an artifact.
     *
     * Fixed on both sides because the stream is chunked and authenticated per chunk; a reader has to
     * use the same size the writer did. Small enough that neither side ever holds much in memory.
     */
    public const ARTIFACT_CHUNK_BYTES = 1048576;

    /**
     * @var string Artifacts whose key was sealed to the platform. The platform can read these.
     *
     * Kept because artifacts written under it still exist and must stay readable. Nothing writes one
     * any more.
     */
    public const BACKUP_FORMAT_V1 = 'v1';

    /**
     * @var string Artifacts whose key was sealed only to an organisation's recovery keys.
     *
     * The platform stores these, verifies them, serves them and deletes them, and cannot open them.
     */
    public const BACKUP_FORMAT_V2 = 'v2';

    /**
     * @var string Oldest connector able to produce a v2 artifact.
     *
     * Served on the signed claim response so a platform can explain, on the site's own screen, why a
     * backup is not happening. It is **not** a security control: the version a connector reports is
     * something it asserts about itself, and a connector that lied would only cause itself to be sent
     * recipients it then has to actually seal to.
     */
    public const MIN_CONNECTOR_VERSION_FOR_V2 = '1.7.0';

    /**
     * @var int Largest artifact manifest, in bytes. See {@see ArtifactEnvelope::MAX_MANIFEST_BYTES}.
     */
    public const MAX_BACKUP_MANIFEST_BYTES = 65536;

    /**
     * @var int Most recovery keys one artifact may be sealed to.
     *
     * Every recipient is another copy of the key that opens the backup, so this is bounded rather than
     * open. Eight is enough for an organisation keeping a working key, a spare in a safe, and one per
     * person who might have to do a restore at three in the morning, without turning a manifest into a
     * keyring.
     */
    public const MAX_BACKUP_RECIPIENTS = 8;

    /**
     * @var int Raw entropy in a request nonce, in bytes.
     */
    public const NONCE_BYTES = 16;

    /**
     * @var int Raw entropy in an enrolment code, in bytes.
     */
    public const ENROLMENT_CODE_BYTES = 32;

    /**
     * @var string Human-visible prefix on an enrolment code, so a leaked one is recognisable.
     */
    public const ENROLMENT_CODE_PREFIX = 'mgr_enrol_';

    // Header names
    // =========================================================================

    public const HEADER_SITE = 'Manager-Site';
    public const HEADER_TIMESTAMP = 'Manager-Timestamp';
    public const HEADER_NONCE = 'Manager-Nonce';
    public const HEADER_CONNECTOR_VERSION = 'Manager-Connector-Version';
    public const HEADER_SIGNATURE = 'Manager-Signature';
    public const HEADER_CORRELATION_ID = 'Manager-Correlation-Id';

    /**
     * @var string SHA-256 of an artifact body, declared up front and covered by the signature.
     *
     * An artifact is too large to hash after the fact and then decide whether to trust it: by then it
     * has already been read. So the connector declares the hash in a header, the signature covers
     * that declaration, and the platform authenticates the request before reading a single byte of
     * the body. The body is then hashed as it streams and rejected if it disagrees.
     *
     * This is the same canonical string as any other request - the body-hash field simply comes from
     * the header rather than from a body already in memory.
     */
    public const HEADER_CONTENT_SHA256 = 'Manager-Content-Sha256';

    /**
     * @var string Value prefix inside the signature header, e.g. "v1=Base64Signature".
     */
    public const SIGNATURE_SCHEME = 'v1';

    /**
     * All headers a signed connector request must carry.
     *
     * @return list<string>
     */
    public static function requiredRequestHeaders(): array
    {
        return [
            self::HEADER_SITE,
            self::HEADER_TIMESTAMP,
            self::HEADER_NONCE,
            self::HEADER_CONNECTOR_VERSION,
            self::HEADER_SIGNATURE,
        ];
    }

    /**
     * Capabilities the platform understands.
     *
     * Phase 1 grants `inventory:read` only; the rest are declared so both sides agree on spelling
     * before they are wired up.
     *
     * @return list<string>
     */
    public static function capabilities(): array
    {
        return [
            'inventory:read',
            'updates:read',
            'licences:read',
            'security:read',
            'system:read',

            // Disk usage, PHP limits and sampled response timings. Deliberately not folded into
            // `system:read`: measuring disk means walking a directory tree and timing responses
            // means observing traffic, and widening an existing grant to cover them would make sites
            // start doing both without anybody deciding to.
            'runtime:read',

            // Counts of failed control-panel sign-ins. Never usernames, never addresses.
            'logins:read',

            'backups:create',
        ];
    }

    /**
     * Capabilities that may be granted automatically during ordinary pairing.
     *
     * Anything that modifies a site, or reads site content, is absent by design: it needs a
     * separate confirmation.
     *
     * @return list<string>
     */
    public static function autoGrantableCapabilities(): array
    {
        return [
            'inventory:read',
            'updates:read',
            'licences:read',
            'security:read',
            'system:read',
            'runtime:read',
            'logins:read',
        ];
    }

    /**
     * Whether a capability is read-only, and so eligible for automatic granting.
     */
    public static function isReadOnlyCapability(string $capability): bool
    {
        return in_array($capability, self::autoGrantableCapabilities(), true);
    }
}
