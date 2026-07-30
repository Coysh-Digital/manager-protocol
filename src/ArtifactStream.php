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
 * Chunked authenticated encryption for backup artifacts.
 *
 * A database backup is the most sensitive thing this system touches, and it is also too large to hold
 * in memory. Both facts point at the same primitive: libsodium's secret stream, which encrypts a file
 * as a sequence of individually authenticated chunks and marks the last one as final.
 *
 * Three properties matter here, and each rules out a simpler option:
 *
 *  - **Per-chunk authentication.** A modified or reordered chunk fails to open. Encrypt-then-MAC over
 *    a whole multi-gigabyte file would mean reading it twice, or trusting it before verifying.
 *  - **A final tag.** The stream records where it ends, so a truncated artifact is detected as
 *    truncated rather than read as a shorter backup. This is the failure that silently produces an
 *    unusable restore, so it is worth the primitive that catches it.
 *  - **Fixed chunk size on both sides.** The reader has to frame the stream the way the writer did,
 *    so the size lives in {@see Protocol::ARTIFACT_CHUNK_BYTES} rather than in either implementation.
 *
 * This class lives in the protocol package because it *is* protocol: the format has to be identical
 * on the connector that writes an artifact and the platform that reads it back, possibly years and
 * several releases apart.
 */
final class ArtifactStream
{
    /**
     * @var string Identifies the format, stored with every artifact.
     *
     * Recorded so that a future change is a new scheme alongside this one rather than a silent
     * reinterpretation of bytes already written. An artifact whose scheme this build does not know is
     * refused, not guessed at.
     */
    public const SCHEME = 'xchacha20poly1305-secretstream-v1';

    /**
     * @var int Raw length of an artifact encryption key, in bytes.
     */
    public const KEY_BYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;

    /**
     * @var int Authentication overhead per chunk, in bytes.
     */
    public const CHUNK_OVERHEAD_BYTES = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

    /**
     * Generate a key for one artifact and no other.
     */
    public static function generateKey(): string
    {
        return sodium_crypto_secretstream_xchacha20poly1305_keygen();
    }

    /**
     * Encrypt a stream, returning everything needed to read it back and verify it.
     *
     * Both hashes are recorded on purpose. The ciphertext hash lets the receiver confirm that what
     * arrived is what was sent, before it has any key with which to look inside. The plaintext hash
     * lets whoever eventually decrypts it confirm they got the backup that was taken, which the
     * ciphertext hash cannot tell them.
     *
     * @param  resource  $input
     * @param  resource  $output
     * @return array{header: string, ciphertext_sha256: string, plaintext_sha256: string, ciphertext_bytes: int, plaintext_bytes: int}
     *
     * @throws ProtocolException
     */
    public static function encrypt($input, $output, #[SensitiveParameter] string $key): array
    {
        self::assertKey($key);

        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);

        $plaintextHash = hash_init('sha256');
        $ciphertextHash = hash_init('sha256');

        // The header goes at the front of the stream and is hashed with it. A receiver verifying the
        // ciphertext hash therefore verifies the header too, which is what stops somebody substituting
        // a header from a different artifact.
        self::write($output, $header);
        hash_update($ciphertextHash, $header);

        $plaintextBytes = 0;
        $ciphertextBytes = strlen($header);

        $chunk = self::read($input);

        // Written so the final chunk is always tagged FINAL, including for an empty input. Deciding
        // "is this the last chunk" after reading the next one is the only way to know without seeking,
        // and seeking is not available on every stream this runs against.
        while (true) {
            $next = self::read($input);
            $isFinal = $next === '';

            $encrypted = sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $chunk,
                '',
                $isFinal
                    ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                    : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
            );

            hash_update($plaintextHash, $chunk);
            hash_update($ciphertextHash, $encrypted);

            $plaintextBytes += strlen($chunk);
            $ciphertextBytes += strlen($encrypted);

            self::write($output, $encrypted);

            if ($isFinal) {
                break;
            }

            $chunk = $next;
        }

        sodium_memzero($state);

        return [
            'header' => base64_encode($header),
            'ciphertext_sha256' => hash_final($ciphertextHash),
            'plaintext_sha256' => hash_final($plaintextHash),
            'ciphertext_bytes' => $ciphertextBytes,
            'plaintext_bytes' => $plaintextBytes,
        ];
    }

    /**
     * Decrypt a stream written by {@see self::encrypt()}.
     *
     * The header is read from the front of the stream rather than passed in, because that is where
     * encrypt() wrote it and where the ciphertext hash covered it.
     *
     * Refuses to finish on a stream that never presented a final tag. A truncated backup that
     * decrypts cleanly up to the cut is the dangerous case: it looks like a backup.
     *
     * @param  resource  $input
     * @param  resource  $output
     * @return array{plaintext_sha256: string, plaintext_bytes: int}
     *
     * @throws ProtocolException
     */
    public static function decrypt($input, $output, #[SensitiveParameter] string $key): array
    {
        self::assertKey($key);

        $header = self::readExactly($input, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

        try {
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        } catch (SodiumException) {
            // A header libsodium will not even accept. Reported as this package's own exception so a
            // caller has one failure type to handle rather than two.
            throw new ProtocolException('This artifact does not begin with a usable header.');
        }

        $plaintextHash = hash_init('sha256');
        $plaintextBytes = 0;
        $sawFinal = false;

        // Chunks are fixed-size on the way in, so they are fixed-size plus overhead on the way out.
        // The final read is short, which is how the loop ends.
        $frameSize = Protocol::ARTIFACT_CHUNK_BYTES + self::CHUNK_OVERHEAD_BYTES;

        while (! feof($input)) {
            $frame = self::readUpTo($input, $frameSize);

            if ($frame === '') {
                break;
            }

            $opened = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $frame);

            if ($opened === false) {
                // Could be a wrong key, a corrupted artifact or a deliberate modification. All three
                // mean the same thing to the caller: do not use this.
                throw new ProtocolException('This artifact failed authentication and was not written.');
            }

            [$chunk, $tag] = $opened;

            hash_update($plaintextHash, $chunk);
            $plaintextBytes += strlen($chunk);

            self::write($output, $chunk);

            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                $sawFinal = true;

                break;
            }
        }

        sodium_memzero($state);

        if (! $sawFinal) {
            throw new ProtocolException(
                'This artifact ended without a final marker, so it is incomplete and was not trusted.'
            );
        }

        return [
            'plaintext_sha256' => hash_final($plaintextHash),
            'plaintext_bytes' => $plaintextBytes,
        ];
    }

    /**
     * @throws ProtocolException
     */
    private static function assertKey(string $key): void
    {
        if (strlen($key) !== self::KEY_BYTES) {
            throw new ProtocolException('Unexpected artifact key length.');
        }
    }

    /**
     * @param  resource  $stream
     */
    private static function read($stream): string
    {
        return self::readUpTo($stream, Protocol::ARTIFACT_CHUNK_BYTES);
    }

    /**
     * Read up to a length, tolerating short reads.
     *
     * fread on a socket or pipe returns what is available rather than what was asked for, so a single
     * call is not enough. Getting this wrong would frame the stream incorrectly and every chunk after
     * the first short read would fail to authenticate.
     *
     * @param  resource  $stream
     */
    private static function readUpTo($stream, int $length): string
    {
        $buffer = '';

        while (true) {
            $remaining = $length - strlen($buffer);

            if ($remaining < 1) {
                break;
            }

            $piece = fread($stream, $remaining);

            if ($piece === false || $piece === '') {
                break;
            }

            $buffer .= $piece;
        }

        return $buffer;
    }

    /**
     * @param  resource  $stream
     *
     * @throws ProtocolException
     */
    private static function readExactly($stream, int $length): string
    {
        $buffer = self::readUpTo($stream, $length);

        if (strlen($buffer) !== $length) {
            throw new ProtocolException('This artifact is too short to be one.');
        }

        return $buffer;
    }

    /**
     * @param  resource  $stream
     *
     * @throws ProtocolException
     */
    private static function write($stream, string $data): void
    {
        $written = 0;
        $length = strlen($data);

        while ($written < $length) {
            $result = fwrite($stream, substr($data, $written));

            // A partial write followed by a failure would otherwise loop forever writing nothing.
            if ($result === false || $result === 0) {
                throw new ProtocolException('Could not write the artifact stream.');
            }

            $written += $result;
        }
    }
}
