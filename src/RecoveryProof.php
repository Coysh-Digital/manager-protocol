<?php

/**
 * Manager protocol.
 *
 * @link      https://coysh.digital
 * @copyright Copyright (c) Coysh Digital
 */

declare(strict_types=1);

namespace coyshdigital\managerprotocol;

use SensitiveParameter;

/**
 * Proving that somebody actually holds the private half of a recovery key.
 *
 * This exists because of how little can be checked about a submitted X25519 public key. Any 32 bytes
 * is a syntactically valid one. A customer can paste in a key they generated on a laptop they have
 * since wiped, a key from a keypair whose secret half was never written to disk, or 32 bytes of
 * something else entirely, and every structural check will pass. They then take backups happily for a
 * year and discover the problem on the one night it matters.
 *
 * So a key is not usable until it has been proven. The ceremony is three steps:
 *
 *  1. The platform generates 32 random bytes, seals them to the submitted public key, stores only the
 *     hash of the *expected response*, and shows the operator the sealed blob.
 *  2. The operator opens it with their private key, offline, using the restore tool, and reads back a
 *     short code.
 *  3. The platform compares hashes. On a match the key becomes usable.
 *
 * Two properties worth naming:
 *
 *  - **The response is a truncated hash of the challenge, not the challenge itself.** The platform can
 *    verify it without ever storing anything that would let somebody else answer, and a response
 *    intercepted in transit reveals nothing about the challenge it came from.
 *
 *  - **The response looks exactly like a fingerprint** - same prefix-and-groups shape, same Crockford
 *    alphabet, same tolerance for how it was retyped. Copying a short code from a terminal into a
 *    browser is the same task as comparing a fingerprint, and it should not come with a second set of
 *    rules to learn.
 *
 * The real value is not cryptographic. It is that enrolling a key becomes a restore rehearsal: the
 * operator has to obtain the tool, find the key file, and run a command that decrypts something. That
 * is the only check that reliably catches a key nobody can actually use.
 */
final class RecoveryProof
{
    /**
     * @var string Domain separation, so a proof response cannot be confused with a fingerprint over
     *             the same bytes.
     */
    public const DOMAIN = 'manager-recovery-proof-v1';

    /**
     * @var int Raw entropy in a challenge, in bytes.
     */
    public const CHALLENGE_BYTES = 32;

    /**
     * Generate a challenge to seal to a candidate public key.
     *
     * @return string base64 of {@see self::CHALLENGE_BYTES} random bytes
     */
    public static function generateChallenge(): string
    {
        return base64_encode(random_bytes(self::CHALLENGE_BYTES));
    }

    /**
     * The answer a holder of the private key should be able to produce.
     *
     * Computed from the challenge *plaintext*, so only somebody who opened the sealed box can arrive
     * at it.
     *
     * @throws ProtocolException if the challenge is not the expected length
     */
    public static function responseFor(#[SensitiveParameter] string $challengePlaintext): string
    {
        if (strlen($challengePlaintext) !== self::CHALLENGE_BYTES) {
            throw new ProtocolException('Unexpected challenge length.');
        }

        $digest = substr(
            hash('sha256', self::DOMAIN . $challengePlaintext, true),
            0,
            KeyFingerprint::TRUNCATED_BYTES,
        );

        return KeyFingerprint::render(KeyFingerprint::PROOF_PREFIX, $digest);
    }

    /**
     * Whether a submitted answer is the right one.
     *
     * Normalised first, so an operator who retyped the code with different separators or a lowercase
     * letter is not told their key is wrong. Constant time, because this is an authentication check
     * even though what it authenticates is possession rather than identity.
     */
    public static function matches(string $submitted, string $expected): bool
    {
        if (! KeyFingerprint::isWellFormed(KeyFingerprint::normalise($expected))) {
            // A malformed expectation can only have come from a bug, and answering "no" to every
            // submission would look exactly like an operator who cannot find their key.
            throw new ProtocolException('The expected proof response is not well formed.');
        }

        return KeyFingerprint::matches($submitted, $expected);
    }
}
