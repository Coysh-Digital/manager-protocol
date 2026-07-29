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
 * Request nonces and enrolment codes.
 *
 * Both are single-use secrets whose only job is to be unguessable, so both come straight from the
 * CSPRNG and are encoded without padding for clean transport.
 */
final class Nonce
{
    /**
     * A fresh request nonce, URL-safe base64 without padding.
     */
    public static function generate(): string
    {
        return self::encode(random_bytes(Protocol::NONCE_BYTES));
    }

    /**
     * Whether a nonce is well formed.
     *
     * Checked before the nonce reaches the replay store, so a malformed value cannot be used to
     * write arbitrary cache keys.
     */
    public static function isValid(string $nonce): bool
    {
        $expectedLength = (int) ceil(Protocol::NONCE_BYTES * 4 / 3);

        return strlen($nonce) === $expectedLength
            && preg_match('~^[A-Za-z0-9_-]+$~', $nonce) === 1;
    }

    /**
     * A fresh enrolment code, shown to the user exactly once.
     */
    public static function generateEnrolmentCode(): string
    {
        return Protocol::ENROLMENT_CODE_PREFIX . self::encode(random_bytes(Protocol::ENROLMENT_CODE_BYTES));
    }

    /**
     * Hash an enrolment code for storage.
     *
     * Plain SHA-256 is right here, and a password hash would be wrong: the code carries 256 bits of
     * CSPRNG entropy, so there is no dictionary to slow an attacker down to, and the pairing
     * endpoint has to consume it in a single indexed statement to stay atomic under concurrency.
     */
    public static function hashEnrolmentCode(string $code): string
    {
        return hash('sha256', $code);
    }

    /**
     * Whether a string looks like an enrolment code, before any database work happens.
     */
    public static function isValidEnrolmentCode(string $code): bool
    {
        if (!str_starts_with($code, Protocol::ENROLMENT_CODE_PREFIX)) {
            return false;
        }

        $body = substr($code, strlen(Protocol::ENROLMENT_CODE_PREFIX));
        $expectedLength = (int) ceil(Protocol::ENROLMENT_CODE_BYTES * 4 / 3);

        return strlen($body) === $expectedLength
            && preg_match('~^[A-Za-z0-9_-]+$~', $body) === 1;
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
