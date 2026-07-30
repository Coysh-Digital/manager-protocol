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
 * The self-describing header that turns an encrypted stream into a backup file.
 *
 * A v1 artifact was a bare {@see ArtifactStream}: bytes that meant nothing without the platform's
 * database row beside them. That was acceptable while the platform held the key. It is not acceptable
 * now, because the whole point of sealing an artifact to a customer's own recovery key is that the
 * customer can open it *without us* — and a file that needs our database to describe itself has not
 * achieved that.
 *
 * So a v2 artifact carries its own manifest:
 *
 * ```
 * offset  bytes  content
 * ------  -----  -----------------------------------------------------------------
 * 0       6      magic, ASCII "MGRBAK"
 * 6       1      format major
 * 7       1      format minor
 * 8       4      manifest length, uint32 big-endian
 * 12      N      manifest, UTF-8 JSON — the exact bytes that were signed
 * 12+N    2      signature length, uint16 big-endian
 * 14+N    S      raw Ed25519 signature by the site's connector key
 * 14+N+S  ...    ArtifactStream output, byte for byte unchanged
 * ```
 *
 * Four things about that layout are load-bearing:
 *
 *  - **Magic first.** `head -c 6` identifies the file, and telling v1 from v2 needs no metadata: a v1
 *    artifact opens with a 24-byte random secretstream header, so the chance of one beginning with
 *    these six bytes is 2^-48. That is the rule both the platform and the restore tool use.
 *
 *  - **Length-prefixed, never delimiter-scanned.** A reader has to find where the encrypted stream
 *    begins without parsing the JSON, and scanning for a closing brace inside a document that may
 *    contain braces is how a parser becomes an attack surface.
 *
 *  - **The manifest is bytes, not an object.** It is serialised once, by the connector, and everything
 *    afterwards carries those exact bytes — into this file, and into the declaration the platform
 *    validates. Nothing re-serialises it. Re-encoding JSON and expecting a signature to survive is the
 *    canonicalisation trap that breaks verification a year later, on a different PHP minor, over a
 *    difference in how a float or a slash was rendered.
 *
 *  - **A domain-separated signature.** Signed over {@see self::MANIFEST_SIGNING_PREFIX} concatenated
 *    with the manifest, so a manifest signature can never be replayed as a request signature and vice
 *    versa. The same reasoning as {@see Protocol::REQUEST_PREFIX} and {@see Protocol::RESPONSE_PREFIX}.
 *
 * The stream itself is untouched. This wraps around {@see ArtifactStream} rather than modifying it,
 * because that class is the one piece of this system with a genuine cross-implementation byte
 * compatibility test, and the change from v1 to v2 is about *who can obtain the key*, not about how
 * bytes are encrypted.
 */
final class ArtifactEnvelope
{
    /**
     * @var string Six bytes that say what this file is.
     */
    public const MAGIC = 'MGRBAK';

    /**
     * @var int Incremented when a reader that understands this version would get the file wrong.
     */
    public const FORMAT_MAJOR = 2;

    /**
     * @var int Incremented for additions a reader of this major version can safely ignore.
     */
    public const FORMAT_MINOR = 0;

    /**
     * @var string Domain separation for the manifest signature.
     */
    public const MANIFEST_SIGNING_PREFIX = "MGRBAK-MANIFEST-v2\n";

    /**
     * @var int Largest manifest this format carries, in bytes.
     *
     * Generous for eight recipients and their metadata, and small enough that a reader can hold one in
     * memory without thinking about it. A manifest larger than this is a bug or an attempt to make a
     * reader allocate, not a backup with a lot to say about itself.
     */
    public const MAX_MANIFEST_BYTES = 65536;

    /**
     * @var int Fixed bytes before the manifest: magic, two version bytes, one length.
     */
    public const PREFIX_BYTES = 12;

    /**
     * Write the envelope to a stream, ready for the encrypted body to follow.
     *
     * Returns the number of bytes written, which is also the offset at which the body begins.
     *
     * @param  resource  $output
     *
     * @throws ProtocolException
     */
    public static function write($output, string $manifestBytes, string $signatureBase64): int
    {
        $length = strlen($manifestBytes);

        if ($length === 0 || $length > self::MAX_MANIFEST_BYTES) {
            throw new ProtocolException('An artifact manifest must be present and within the size limit.');
        }

        $signature = base64_decode($signatureBase64, true);

        if ($signature === false || strlen($signature) !== Keys::SIGNATURE_BYTES) {
            throw new ProtocolException('An artifact manifest signature is not the expected length.');
        }

        $header = self::MAGIC
            . chr(self::FORMAT_MAJOR)
            . chr(self::FORMAT_MINOR)
            . pack('N', $length)
            . $manifestBytes
            . pack('n', Keys::SIGNATURE_BYTES)
            . $signature;

        self::write_($output, $header);

        return strlen($header);
    }

    /**
     * Read the envelope from the front of a stream, leaving it positioned at the encrypted body.
     *
     * @param  resource  $input
     * @return array{manifest_bytes: string, signature: string, body_offset: int}
     *
     * @throws ProtocolException
     */
    public static function readHeader($input): array
    {
        $prefix = self::readExactly($input, self::PREFIX_BYTES);

        if (! hash_equals(self::MAGIC, substr($prefix, 0, strlen(self::MAGIC)))) {
            throw new ProtocolException('This file does not begin like a Manager backup artifact.');
        }

        $major = ord($prefix[6]);

        if ($major !== self::FORMAT_MAJOR) {
            // Named rather than guessed at. A reader that quietly attempts a format it does not know
            // is how a corrupt restore gets mistaken for a corrupt backup.
            throw new ProtocolException(
                "This artifact is format version {$major}, which this build does not read."
            );
        }

        // The minor version is deliberately not checked. That is what a minor version is for: a reader
        // of this major version can ignore anything added under one.

        /** @var array{1: int} $unpackedLength */
        $unpackedLength = unpack('N', substr($prefix, 8, 4));
        $manifestLength = $unpackedLength[1];

        if ($manifestLength === 0 || $manifestLength > self::MAX_MANIFEST_BYTES) {
            // Checked before the read, not after. A declared length is an allocation request from
            // somebody who has not been authenticated yet.
            throw new ProtocolException('This artifact declares a manifest length outside the permitted range.');
        }

        $manifest = self::readExactly($input, $manifestLength);

        /** @var array{1: int} $unpackedSignature */
        $unpackedSignature = unpack('n', self::readExactly($input, 2));
        $signatureLength = $unpackedSignature[1];

        if ($signatureLength !== Keys::SIGNATURE_BYTES) {
            throw new ProtocolException('This artifact declares a manifest signature of the wrong length.');
        }

        $signature = self::readExactly($input, $signatureLength);

        return [
            'manifest_bytes' => $manifest,
            'signature' => base64_encode($signature),
            'body_offset' => self::PREFIX_BYTES + $manifestLength + 2 + $signatureLength,
        ];
    }

    /**
     * Whether these opening bytes belong to a v2 artifact rather than a bare v1 stream.
     *
     * Answered from the first six bytes, so a caller can decide what to do with a file before
     * committing to a parser for it.
     */
    public static function isEnvelope(string $firstBytes): bool
    {
        return strlen($firstBytes) >= strlen(self::MAGIC)
            && hash_equals(self::MAGIC, substr($firstBytes, 0, strlen(self::MAGIC)));
    }

    /**
     * Sign a manifest with a site's connector signing key.
     *
     * @throws ProtocolException
     */
    public static function signManifest(
        string $manifestBytes,
        #[SensitiveParameter] string $secretKeyBase64,
    ): string {
        return Keys::sign(self::MANIFEST_SIGNING_PREFIX . $manifestBytes, $secretKeyBase64);
    }

    /**
     * Verify a manifest signature against a site's connector public key.
     *
     * Returns false rather than throwing, for the reason {@see Keys::verify()} gives: a caller checking
     * an attacker-supplied signature should get a plain no.
     */
    public static function verifyManifest(
        string $manifestBytes,
        string $signatureBase64,
        string $publicKeyBase64,
    ): bool {
        return Keys::verify(
            self::MANIFEST_SIGNING_PREFIX . $manifestBytes,
            $signatureBase64,
            $publicKeyBase64,
        );
    }

    /**
     * Read exactly this many bytes or fail.
     *
     * Deliberately a private copy of the loop in {@see ArtifactStream}, rather than that class exposing
     * it. ArtifactStream is the one class here with a byte-compatibility contract across three
     * implementations, and widening its surface to share twenty lines would put a stable thing at risk
     * to save duplicating an unstable amount of nothing.
     *
     * @param  resource  $stream
     *
     * @throws ProtocolException
     */
    private static function readExactly($stream, int $length): string
    {
        $buffer = '';

        while (true) {
            $remaining = $length - strlen($buffer);

            if ($remaining < 1) {
                break;
            }

            // fread on a socket or a pipe returns what is available rather than what was asked for,
            // so one call is never enough.
            $piece = fread($stream, $remaining);

            if ($piece === false || $piece === '') {
                break;
            }

            $buffer .= $piece;
        }

        if (strlen($buffer) !== $length) {
            throw new ProtocolException('This artifact ended part way through its header.');
        }

        return $buffer;
    }

    /**
     * @param  resource  $stream
     *
     * @throws ProtocolException
     */
    private static function write_($stream, string $data): void
    {
        $written = 0;
        $length = strlen($data);

        while ($written < $length) {
            $result = fwrite($stream, substr($data, $written));

            // A partial write followed by a failure would otherwise loop forever writing nothing.
            if ($result === false || $result === 0) {
                throw new ProtocolException('Could not write the artifact envelope.');
            }

            $written += $result;
        }
    }
}
