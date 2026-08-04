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
 * Short, human-checkable names for public keys.
 *
 * A recovery key is the one piece of this system a customer has to compare by eye. They hold a file
 * on a laptop, a line in `config/manager-connector.php` on their Craft server, and a row on a screen
 * the platform renders, and the whole security of zero-knowledge backups rests on the first two
 * agreeing. Forty-four characters of base64 is not something a person compares reliably, so keys get
 * a fingerprint instead.
 *
 * Four decisions, each of which rules out an easier option:
 *
 *  - **Domain-separated hashing.** The fingerprint is over a context string concatenated with the raw
 *    key, not over the key alone. A site's Ed25519 signing key and an organisation's X25519 recovery
 *    key are different kinds of thing, and hashing them the same way would let one be compared against
 *    the other and appear to match if they ever shared bytes. They cannot be cross-compared here
 *    because they do not share a hash input.
 *
 *  - **Fifteen bytes, not sixteen or twenty.** 120 bits is exactly 24 Crockford base32 characters,
 *    which is exactly six groups of four with no ragged final group. The property being relied on is
 *    second preimage resistance - finding a *different* public key with this fingerprint - at 2^120.
 *    Collision resistance, at 2^60, is not what protects anything here: a fingerprint is only ever
 *    compared against one the customer already holds.
 *
 *  - **Crockford base32, not hex and not base64.** The alphabet excludes I, L, O and U, so there is no
 *    1/I or 0/O ambiguity when somebody reads one aloud over the phone or retypes it into a
 *    configuration file. Hex would be 30 characters and base64 would be case-sensitive.
 *
 *  - **One canonical form everywhere.** Wire, database, display, config file. Not hex on the wire and
 *    base32 on screen, because that is where comparison bugs live.
 */
final class KeyFingerprint
{
    /**
     * @var string Prefix on an organisation recovery key fingerprint.
     */
    public const RECOVERY_PREFIX = 'MGRK';

    /**
     * @var string Prefix on a site connector signing key fingerprint.
     */
    public const SITE_PREFIX = 'MGRS';

    /**
     * @var string Prefix on a recovery-key proof-of-possession response. See {@see RecoveryProof}.
     */
    public const PROOF_PREFIX = 'MGRP';

    /**
     * @var string Domain separation for recovery keys. Changing this invalidates every fingerprint
     *             ever displayed, so it is a wire-format change.
     */
    public const RECOVERY_DOMAIN = 'manager-recovery-key-v1';

    /**
     * @var string Domain separation for site signing keys.
     */
    public const SITE_DOMAIN = 'manager-site-key-v1';

    /**
     * @var int Bytes of hash kept. 15 bytes is 120 bits is 24 base32 characters exactly.
     */
    public const TRUNCATED_BYTES = 15;

    /**
     * @var int Characters per hyphen-separated group.
     */
    public const GROUP_SIZE = 4;

    /**
     * @var string Crockford base32. No I, L, O or U.
     */
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    /**
     * Fingerprint an organisation recovery key.
     *
     * @throws ProtocolException if the key is not a well-formed X25519 public key
     */
    public static function forRecoveryKey(string $x25519PublicKeyBase64): string
    {
        $raw = base64_decode($x25519PublicKeyBase64, true);

        if ($raw === false || strlen($raw) !== Sealing::BOX_PUBLIC_KEY_BYTES) {
            // The value is never quoted back. A malformed key is usually a paste error, and echoing
            // it into a log or an exception is how key material ends up somewhere it was not meant
            // to be - even a public one, which still identifies an organisation.
            throw new ProtocolException('Not a well-formed recovery public key.');
        }

        return self::forKey(self::RECOVERY_PREFIX, self::RECOVERY_DOMAIN, $raw);
    }

    /**
     * Fingerprint a site's connector signing key.
     *
     * @throws ProtocolException if the key is not a well-formed Ed25519 public key
     */
    public static function forSiteKey(string $ed25519PublicKeyBase64): string
    {
        $raw = base64_decode($ed25519PublicKeyBase64, true);

        if ($raw === false || strlen($raw) !== Keys::PUBLIC_KEY_BYTES) {
            throw new ProtocolException('Not a well-formed site public key.');
        }

        return self::forKey(self::SITE_PREFIX, self::SITE_DOMAIN, $raw);
    }

    /**
     * Whether a string is a fingerprint this package would have produced.
     *
     * Shape only. A well-formed fingerprint is not necessarily one that names a key anybody holds.
     */
    public static function isWellFormed(string $fingerprint): bool
    {
        $prefixes = implode('|', [self::RECOVERY_PREFIX, self::SITE_PREFIX, self::PROOF_PREFIX]);

        return preg_match(
            '~^(' . $prefixes . ')(-[0-9A-HJKMNP-TV-Z]{' . self::GROUP_SIZE . '}){6}\z~',
            $fingerprint,
        ) === 1;
    }

    /**
     * Render arbitrary digest bytes in the shared prefix-and-groups form.
     *
     * Public so that {@see RecoveryProof} produces something that looks and behaves exactly like a
     * fingerprint - same length, same alphabet, same normalisation, same tolerance for how somebody
     * retyped it. A customer completing a proof-of-possession ceremony is copying a short code between
     * a terminal and a browser, which is the same task as comparing a fingerprint, and it should not
     * come with a second set of rules.
     *
     * @throws ProtocolException if the digest is not the expected length
     */
    public static function render(string $prefix, string $digest): string
    {
        if (strlen($digest) !== self::TRUNCATED_BYTES) {
            throw new ProtocolException('Unexpected digest length for a fingerprint.');
        }

        return $prefix . '-' . implode('-', str_split(self::encodeBase32($digest), self::GROUP_SIZE));
    }

    /**
     * Put a fingerprint somebody typed into canonical form.
     *
     * Crockford's decoding rules, which exist for exactly this situation: I and L both mean 1, O means
     * 0, case is irrelevant, and separators are decoration. U is not accepted - it is excluded from
     * the alphabet rather than aliased, so a U is a genuine mistake rather than a near miss.
     *
     * The result is not guaranteed to be well formed; ask {@see self::isWellFormed()} about that. This
     * only removes the differences that are not differences.
     */
    public static function normalise(string $typed): string
    {
        $upper = strtoupper($typed);

        // Everything that is not a letter or digit is a separator, whatever the person used.
        $stripped = (string) preg_replace('~[^A-Z0-9]~', '', $upper);

        $mapped = strtr($stripped, ['I' => '1', 'L' => '1', 'O' => '0']);

        $expected = strlen(self::RECOVERY_PREFIX) + self::characterCount();

        if (strlen($mapped) !== $expected) {
            // Returned as-is rather than padded or truncated. A wrong-length fingerprint should fail
            // the comparison it is about to be used in, not be quietly reshaped into something that
            // might pass one.
            return $mapped;
        }

        $prefix = substr($mapped, 0, strlen(self::RECOVERY_PREFIX));
        $body = substr($mapped, strlen(self::RECOVERY_PREFIX));

        return $prefix . '-' . implode('-', str_split($body, self::GROUP_SIZE));
    }

    /**
     * Whether two fingerprints name the same key, allowing for how they were typed.
     *
     * Constant time over the normalised forms. The comparison is not secret - a fingerprint is public
     * - but this is the check that decides whether a site will seal a database to a key, and a
     * comparison that returns early is a habit worth not having in that position.
     */
    public static function matches(string $a, string $b): bool
    {
        return hash_equals(self::normalise($a), self::normalise($b));
    }

    /**
     * How many base32 characters the truncated hash occupies.
     */
    private static function characterCount(): int
    {
        return intdiv(self::TRUNCATED_BYTES * 8, 5);
    }

    /**
     * @param  non-empty-string  $rawKey
     *
     * @throws ProtocolException
     */
    private static function forKey(string $prefix, string $domain, string $rawKey): string
    {
        return self::render($prefix, substr(hash('sha256', $domain . $rawKey, true), 0, self::TRUNCATED_BYTES));
    }

    /**
     * Crockford base32, most significant bit first, no padding.
     *
     * Hand-written rather than taken from a dependency because this package has none and is not about
     * to acquire one for thirty lines of bit shifting.
     */
    private static function encodeBase32(string $bytes): string
    {
        $out = '';
        $buffer = 0;
        $bits = 0;

        for ($i = 0, $length = strlen($bytes); $i < $length; $i++) {
            $buffer = ($buffer << 8) | ord($bytes[$i]);
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::ALPHABET[($buffer >> $bits) & 0x1F];
            }
        }

        // Fifteen bytes is 120 bits, a whole number of 5-bit groups, so this never runs today. It is
        // here because a future truncation length that is not a multiple of five would otherwise
        // silently discard the trailing bits rather than fail.
        if ($bits > 0) {
            $out .= self::ALPHABET[($buffer << (5 - $bits)) & 0x1F];
        }

        return $out;
    }
}
