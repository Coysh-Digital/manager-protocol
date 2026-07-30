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
use SodiumException;

/**
 * Anonymous sealed boxes, for handing a key to the platform without a shared secret.
 *
 * A connector generates a fresh key for every artifact it encrypts, and that key has to reach the
 * platform somehow. A sealed box is the right shape for this: it needs only the recipient's public
 * key, which the connector already holds from pairing, and it produces something only the holder of
 * the matching secret key can open. The connector cannot read back what it sealed, which is a
 * property rather than a limitation — a compromised site cannot recover the keys to artifacts it
 * uploaded last month.
 *
 * These are X25519 keys, separate from the Ed25519 keys used for signing. Using one keypair for both
 * signing and encryption is a well-known way to weaken both, so the platform holds two.
 */
final class Sealing
{
    /**
     * @var int Raw length of an X25519 public key, in bytes.
     */
    public const BOX_PUBLIC_KEY_BYTES = 32;

    /**
     * @var int Raw length of an X25519 secret key, in bytes.
     */
    public const BOX_SECRET_KEY_BYTES = 32;

    /**
     * @var int Overhead a sealed box adds: an ephemeral public key and an authentication tag.
     */
    public const SEAL_OVERHEAD_BYTES = 48;

    /**
     * Generate the platform's encryption keypair.
     *
     * @return array{public: string, secret: string} both base64
     */
    public static function generateBoxKeypair(): array
    {
        $keypair = sodium_crypto_box_keypair();

        $result = [
            'public' => base64_encode(sodium_crypto_box_publickey($keypair)),
            'secret' => base64_encode(sodium_crypto_box_secretkey($keypair)),
        ];

        sodium_memzero($keypair);

        return $result;
    }

    /**
     * Seal a short secret to a public key.
     *
     * @throws ProtocolException if the public key is not well formed
     */
    public static function seal(#[SensitiveParameter] string $plaintext, string $publicKeyBase64): string
    {
        $public = self::decode($publicKeyBase64, self::BOX_PUBLIC_KEY_BYTES, 'box public key');

        return base64_encode(sodium_crypto_box_seal($plaintext, $public));
    }

    /**
     * Open a sealed secret.
     *
     * Unsealing needs both halves of the recipient keypair, which is how libsodium's anonymous boxes
     * work: the sender's identity is not recorded, so there is nothing to verify it against.
     *
     * @throws ProtocolException if the keys are malformed or the box does not open
     */
    public static function unseal(
        string $sealedBase64,
        string $publicKeyBase64,
        #[SensitiveParameter] string $secretKeyBase64,
    ): string {
        $sealed = base64_decode($sealedBase64, true);

        if ($sealed === false || strlen($sealed) <= self::SEAL_OVERHEAD_BYTES) {
            throw new ProtocolException('Malformed sealed key.');
        }

        $public = self::decode($publicKeyBase64, self::BOX_PUBLIC_KEY_BYTES, 'box public key');
        $secret = self::decode($secretKeyBase64, self::BOX_SECRET_KEY_BYTES, 'box secret key');

        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($secret, $public);

        $plaintext = sodium_crypto_box_seal_open($sealed, $keypair);

        sodium_memzero($secret);
        sodium_memzero($keypair);

        // A wrong key and a tampered box are indistinguishable from here, which is correct.
        if ($plaintext === false) {
            throw new ProtocolException('Could not open this sealed key.');
        }

        return $plaintext;
    }

    /**
     * Whether a string is a well-formed base64 X25519 public key.
     *
     * Shape only, and that is nearly all "well formed" can mean here: any 32 bytes is a syntactically
     * valid X25519 public key. See {@see self::isUsableBoxPublicKey()} for the stronger question.
     */
    public static function isValidBoxPublicKey(string $publicKeyBase64): bool
    {
        try {
            self::decode($publicKeyBase64, self::BOX_PUBLIC_KEY_BYTES, 'box public key');
        } catch (ProtocolException) {
            return false;
        }

        return true;
    }

    /**
     * Whether a public key is one this package could actually seal to.
     *
     * Well-formedness is a weak test, so this adds the one further check available: that the key is not
     * a small-order point. Sealing to such a key produces a box anybody can open, because the ephemeral
     * key agreement yields a shared secret an attacker can predict.
     *
     * **This is not the control that prevents that attack.** libsodium already refuses — `crypto_box_seal`
     * on a small-order key throws, because `crypto_scalarmult` returns an error rather than a usable
     * secret. What this method buys is *when* the refusal happens. Without it, a recovery key entered
     * by hand looks fine until the night a site has already dumped its database to disk and is trying
     * to seal the artifact key, at which point the job fails somewhere unhelpful. With it, the key is
     * refused at enrolment, next to the field it was typed into.
     *
     * The probe is a scalar multiplication with a throwaway secret. Both outcomes are treated as
     * rejection: libsodium raises `SodiumException` on the canonical small-order points, and the
     * all-zero comparison covers a build that returned the degenerate result instead of erroring.
     *
     * A caveat worth stating rather than leaving to be discovered: the widely circulated list of
     * "twelve small-order points" includes five non-canonical encodings with the high bit set. RFC 7748
     * requires that bit to be masked, so those reduce to ordinary field elements and are neither
     * refused here nor dangerous. The seven canonical ones are what matters and are all rejected.
     */
    public static function isUsableBoxPublicKey(string $publicKeyBase64): bool
    {
        try {
            $public = self::decode($publicKeyBase64, self::BOX_PUBLIC_KEY_BYTES, 'box public key');
        } catch (ProtocolException) {
            return false;
        }

        $probe = sodium_crypto_box_secretkey(sodium_crypto_box_keypair());

        try {
            $shared = sodium_crypto_scalarmult($probe, $public);
        } catch (SodiumException) {
            return false;
        } finally {
            sodium_memzero($probe);
        }

        $degenerate = hash_equals(str_repeat("\0", self::BOX_PUBLIC_KEY_BYTES), $shared);

        sodium_memzero($shared);

        return ! $degenerate;
    }

    /**
     * @return non-empty-string
     *
     * @throws ProtocolException
     */
    private static function decode(string $value, int $expectedBytes, string $label): string
    {
        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            throw new ProtocolException("Malformed base64 in {$label}.");
        }

        if ($decoded === '' || strlen($decoded) !== $expectedBytes) {
            throw new ProtocolException("Unexpected {$label} length.");
        }

        return $decoded;
    }
}
