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
 * Ed25519 key handling.
 *
 * Wraps libsodium, which ships with PHP, so neither the platform nor the connector takes a
 * cryptography dependency. Keys cross the wire and sit in configuration as base64, and are only
 * ever raw bytes inside a single function call.
 */
final class Keys
{
    /**
     * @var int Raw length of an Ed25519 public key, in bytes.
     */
    public const PUBLIC_KEY_BYTES = 32;

    /**
     * @var int Raw length of an Ed25519 secret key, in bytes.
     */
    public const SECRET_KEY_BYTES = 64;

    /**
     * @var int Raw length of an Ed25519 signature, in bytes.
     */
    public const SIGNATURE_BYTES = 64;

    /**
     * Generate a fresh keypair.
     *
     * The connector calls this locally during pairing. The secret half never leaves the machine
     * that generated it.
     *
     * @return array{public: string, secret: string} both base64
     */
    public static function generateKeypair(): array
    {
        $keypair = sodium_crypto_sign_keypair();

        $result = [
            'public' => base64_encode(sodium_crypto_sign_publickey($keypair)),
            'secret' => base64_encode(sodium_crypto_sign_secretkey($keypair)),
        ];

        sodium_memzero($keypair);

        return $result;
    }

    /**
     * Sign a message, returning a base64 signature.
     *
     * @throws ProtocolException if the key is not a well-formed Ed25519 secret key
     */
    public static function sign(string $message, #[SensitiveParameter] string $secretKeyBase64): string
    {
        $secret = self::decode($secretKeyBase64, self::SECRET_KEY_BYTES, 'secret key');

        $signature = sodium_crypto_sign_detached($message, $secret);

        sodium_memzero($secret);

        return base64_encode($signature);
    }

    /**
     * Verify a base64 signature against a base64 public key.
     *
     * Returns false rather than throwing on malformed input: a caller verifying an attacker-supplied
     * signature should get a plain "no", not an exception that behaves differently from a bad
     * signature and leaks which of the two it was.
     */
    public static function verify(string $message, string $signatureBase64, string $publicKeyBase64): bool
    {
        try {
            $signature = self::decode($signatureBase64, self::SIGNATURE_BYTES, 'signature');
            $public = self::decode($publicKeyBase64, self::PUBLIC_KEY_BYTES, 'public key');
        } catch (ProtocolException) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $message, $public);
    }

    /**
     * Whether a string is a well-formed base64 Ed25519 public key.
     */
    public static function isValidPublicKey(string $publicKeyBase64): bool
    {
        try {
            self::decode($publicKeyBase64, self::PUBLIC_KEY_BYTES, 'public key');
        } catch (ProtocolException) {
            return false;
        }

        return true;
    }

    /**
     * Strict base64 decode with a length check.
     *
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
