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
