<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\ArtifactStream;
use coyshdigital\managerprotocol\Protocol;
use coyshdigital\managerprotocol\ProtocolException;
use coyshdigital\managerprotocol\Sealing;

/**
 * Artifact encryption, tested as a format rather than as a function.
 *
 * These run on both sides of the wire and years apart, so what is asserted here is that a stream one
 * build writes is one a later build reads back byte for byte — and, just as importantly, that the
 * ways an artifact can be wrong are all detected rather than any of them being read as a shorter
 * backup.
 */
/**
 * @return resource
 */
function memoryStream(string $contents = '')
{
    $stream = fopen('php://memory', 'r+b');

    if ($stream === false) {
        throw new RuntimeException('Could not open a memory stream.');
    }

    if ($contents !== '') {
        fwrite($stream, $contents);
    }

    rewind($stream);

    return $stream;
}

/**
 * @param  resource  $stream
 */
function streamContents($stream): string
{
    rewind($stream);

    return (string) stream_get_contents($stream);
}

it('round-trips a payload', function (int $bytes): void {
    $plaintext = random_bytes($bytes);
    $key = ArtifactStream::generateKey();

    $in = memoryStream($plaintext);
    $ciphertext = memoryStream();

    $written = ArtifactStream::encrypt($in, $ciphertext, $key);

    expect($written['plaintext_bytes'])->toBe($bytes)
        ->and($written['plaintext_sha256'])->toBe(hash('sha256', $plaintext))
        ->and($written['ciphertext_sha256'])->toBe(hash('sha256', streamContents($ciphertext)));

    $out = memoryStream();
    $read = ArtifactStream::decrypt(memoryStream(streamContents($ciphertext)), $out, $key);

    expect(streamContents($out))->toBe($plaintext)
        ->and($read['plaintext_sha256'])->toBe($written['plaintext_sha256'])
        ->and($read['plaintext_bytes'])->toBe($bytes);
})->with([
    // Sizes chosen around the chunk boundary, because off-by-one framing is the bug this catches.
    'one byte' => 1,
    'under one chunk' => 1024,
    'exactly one chunk' => Protocol::ARTIFACT_CHUNK_BYTES,
    'one chunk and a byte' => Protocol::ARTIFACT_CHUNK_BYTES + 1,
    'several chunks' => (Protocol::ARTIFACT_CHUNK_BYTES * 2) + 4096,
]);

it('refuses a truncated artifact rather than returning a shorter backup', function (): void {
    $key = ArtifactStream::generateKey();

    $ciphertext = memoryStream();
    ArtifactStream::encrypt(memoryStream(random_bytes(Protocol::ARTIFACT_CHUNK_BYTES * 2)), $ciphertext, $key);

    $full = streamContents($ciphertext);

    // Cut on a chunk boundary, so every chunk present still authenticates. This is the dangerous
    // case: without the final marker it would decrypt cleanly and look like a smaller backup.
    $cut = substr($full, 0, Protocol::ARTIFACT_CHUNK_BYTES + ArtifactStream::CHUNK_OVERHEAD_BYTES
        + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

    expect(fn () => ArtifactStream::decrypt(memoryStream($cut), memoryStream(), $key))
        ->toThrow(ProtocolException::class, 'incomplete');
});

it('refuses an artifact whose bytes were altered', function (): void {
    $key = ArtifactStream::generateKey();

    $ciphertext = memoryStream();
    ArtifactStream::encrypt(memoryStream(random_bytes(4096)), $ciphertext, $key);

    $bytes = streamContents($ciphertext);

    // Invert the byte rather than assigning a constant. The key is fresh every run, so this byte is
    // effectively uniform random -- and assigning "\x00" to a byte that already held "\x00" is not a
    // tamper at all. About one run in 256 the artifact stayed intact, decrypted cleanly, and the test
    // failed for having proved nothing.
    $offset = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES + 10;
    $bytes[$offset] = chr(ord($bytes[$offset]) ^ 0xFF);

    expect(fn () => ArtifactStream::decrypt(memoryStream($bytes), memoryStream(), $key))
        ->toThrow(ProtocolException::class, 'failed authentication');
});

it('refuses an artifact whose header came from another artifact', function (): void {
    $key = ArtifactStream::generateKey();

    $first = memoryStream();
    ArtifactStream::encrypt(memoryStream(random_bytes(4096)), $first, $key);

    $second = memoryStream();
    ArtifactStream::encrypt(memoryStream(random_bytes(4096)), $second, $key);

    $headerBytes = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;

    // Same key, different stream. Splicing one header onto another's body must not open.
    $spliced = substr(streamContents($first), 0, $headerBytes).substr(streamContents($second), $headerBytes);

    expect(fn () => ArtifactStream::decrypt(memoryStream($spliced), memoryStream(), $key))
        ->toThrow(ProtocolException::class);
});

it('refuses the wrong key', function (): void {
    $ciphertext = memoryStream();
    ArtifactStream::encrypt(memoryStream(random_bytes(4096)), $ciphertext, ArtifactStream::generateKey());

    expect(fn () => ArtifactStream::decrypt(
        memoryStream(streamContents($ciphertext)),
        memoryStream(),
        ArtifactStream::generateKey(),
    ))->toThrow(ProtocolException::class);
});

it('produces a different ciphertext every time for identical input', function (): void {
    $plaintext = random_bytes(4096);
    $key = ArtifactStream::generateKey();

    $first = memoryStream();
    $second = memoryStream();

    $a = ArtifactStream::encrypt(memoryStream($plaintext), $first, $key);
    $b = ArtifactStream::encrypt(memoryStream($plaintext), $second, $key);

    // Same key, same input, different bytes — the header carries a fresh nonce. Two nightly backups
    // of an unchanged database must not be visibly identical in storage.
    expect(streamContents($first))->not->toBe(streamContents($second))
        ->and($a['ciphertext_sha256'])->not->toBe($b['ciphertext_sha256'])
        // The plaintext hash is the same, which is how a reader confirms they got the same backup.
        ->and($a['plaintext_sha256'])->toBe($b['plaintext_sha256']);
});

it('rejects a key of the wrong length', function (): void {
    expect(fn () => ArtifactStream::encrypt(memoryStream('x'), memoryStream(), 'short'))
        ->toThrow(ProtocolException::class, 'key length');
});

it('names its scheme so a format change cannot be mistaken for this one', function (): void {
    // Stored with every artifact. A build that does not recognise the scheme refuses the artifact
    // rather than guessing at the bytes.
    expect(ArtifactStream::SCHEME)->toBe('xchacha20poly1305-secretstream-v1');
});

it('seals an artifact key so only the platform can open it', function (): void {
    $platform = Sealing::generateBoxKeypair();
    $key = ArtifactStream::generateKey();

    $sealed = Sealing::seal($key, $platform['public']);

    expect(Sealing::unseal($sealed, $platform['public'], $platform['secret']))->toBe($key);

    // The connector holds only the public half, so it cannot reopen what it sealed. A site compromised
    // later cannot recover the keys to artifacts it uploaded earlier.
    $other = Sealing::generateBoxKeypair();

    expect(fn () => Sealing::unseal($sealed, $other['public'], $other['secret']))
        ->toThrow(ProtocolException::class);
});

it('seals differently every time', function (): void {
    $platform = Sealing::generateBoxKeypair();
    $key = ArtifactStream::generateKey();

    // An ephemeral sender keypair per seal, so two artifacts sharing a key would not be detectable
    // as sharing one.
    expect(Sealing::seal($key, $platform['public']))
        ->not->toBe(Sealing::seal($key, $platform['public']));
});

it('rejects a malformed box public key', function (string $value): void {
    expect(Sealing::isValidBoxPublicKey($value))->toBeFalse();
})->with([
    'not base64' => 'not base64 at all!',
    'wrong length' => 'c2hvcnQ=',
    'empty' => '',
]);

it('refuses a public key that would produce a box anybody could open', function (string $hex, string $why): void {
    $key = base64_encode((string) hex2bin($hex));

    // Small-order Curve25519 points. Sealing to one produces a shared secret an attacker can predict,
    // so the box is readable by anyone who finds it.
    //
    // This is not the control that prevents the attack — libsodium already refuses, which the second
    // expectation asserts rather than assumes. What this buys is *when*: a recovery key entered by hand
    // is refused next to the field it was typed into, instead of at three in the morning on the night a
    // site has already dumped its database to disk and cannot seal the artifact key.
    expect(Sealing::isUsableBoxPublicKey($key))->toBeFalse($why)
        ->and(Sealing::isValidBoxPublicKey($key))->toBeTrue('shape alone cannot catch this');

    expect(fn (): string => Sealing::seal('a key', $key))->toThrow(SodiumException::class);
})->with([
    'the identity' => ['0000000000000000000000000000000000000000000000000000000000000000', 'all zero'],
    'order one' => ['0100000000000000000000000000000000000000000000000000000000000000', 'one'],
    'order eight' => ['e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'order 8'],
    'order eight, the other one' => ['5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157', 'order 8'],
    'p minus one' => ['ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'p-1'],
    'p' => ['edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'p'],
    'p plus one' => ['eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'p+1'],
]);

it('accepts a key that was actually generated', function (): void {
    for ($i = 0; $i < 50; $i++) {
        expect(Sealing::isUsableBoxPublicKey(Sealing::generateBoxKeypair()['public']))->toBeTrue();
    }
});

it('treats a malformed key as unusable rather than raising', function (string $value): void {
    expect(Sealing::isUsableBoxPublicKey($value))->toBeFalse();
})->with([
    'not base64' => 'not base64 at all!',
    'wrong length' => 'c2hvcnQ=',
    'empty' => '',
    'an Ed25519 secret key' => 'bWFuYWdlci1wcm90b2NvbC10ZXN0LXNlZWQwMDAwMDDC1NC1y2RWLUrF6iXb3OYHElmJM/fkQXoDnUsBvXaxGw==',
]);
