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
    public const VERSION = '1.0.0';

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
