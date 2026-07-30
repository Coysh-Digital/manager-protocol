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
    public const VERSION = '1.0.1';

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
     * @var int Largest backup artifact the platform will accept, in bytes.
     *
     * A backup does not travel as a payload — it is streamed, on its own route, and the ordinary
     * payload cap would refuse it before it started. This is the separate ceiling for that route.
     *
     * The number is a deliberate policy statement rather than a technical limit: an artifact larger
     * than this is a site whose backup strategy needs a conversation, not a bigger buffer.
     */
    public const MAX_ARTIFACT_BYTES = 2147483648;

    /**
     * @var int Bytes per chunk when encrypting or decrypting an artifact.
     *
     * Fixed on both sides because the stream is chunked and authenticated per chunk; a reader has to
     * use the same size the writer did. Small enough that neither side ever holds much in memory.
     */
    public const ARTIFACT_CHUNK_BYTES = 1048576;

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
     * This is the same canonical string as any other request — the body-hash field simply comes from
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
