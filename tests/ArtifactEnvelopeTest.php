<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\ArtifactEnvelope;
use coyshdigital\managerprotocol\ArtifactStream;
use coyshdigital\managerprotocol\KeyFingerprint;
use coyshdigital\managerprotocol\Keys;
use coyshdigital\managerprotocol\Protocol;
use coyshdigital\managerprotocol\ProtocolException;
use coyshdigital\managerprotocol\SchemaValidator;
use coyshdigital\managerprotocol\Sealing;

/**
 * The envelope is what makes a v2 artifact a file rather than a row.
 *
 * A v1 artifact meant nothing without the platform's database beside it, which was tolerable while the
 * platform held the key. It is not tolerable now. The test that matters most in this file is the one
 * that opens `envelope.v2/artifact.bin` with nothing but a private key and reads the original dump back
 * out — because that is the customer's position, and if it fails, zero-knowledge is a slogan.
 */
it('opens the reference artifact with a private key and nothing else', function (): void {
    $reference = fixture('envelope.v2/reference.json');
    $path = dirname(__DIR__) . '/fixtures/envelope.v2/artifact.bin';

    $handle = fopen($path, 'rb');
    $envelope = ArtifactEnvelope::readHeader($handle);

    // Nothing here consults a platform. Everything needed came out of the file.
    $manifest = json_decode($envelope['manifest_bytes'], true, 512, JSON_THROW_ON_ERROR);

    $recipient = $manifest['key_wrapping']['recipients'][0];

    $key = Sealing::unseal(
        $recipient['wrapped_key'],
        $reference['keys']['recovery_a']['public'],
        $reference['keys']['recovery_a']['secret'],
    );

    $output = fopen('php://memory', 'w+b');
    $result = ArtifactStream::decrypt($handle, $output, $key);
    rewind($output);
    $plaintext = stream_get_contents($output);

    fclose($handle);
    fclose($output);

    expect($plaintext)->toBe($reference['plaintext'])
        ->and($result['plaintext_sha256'])->toBe($manifest['integrity']['plaintext_sha256']);
});

it('opens the reference artifact with either recovery key', function (string $which): void {
    $reference = fixture('envelope.v2/reference.json');
    $path = dirname(__DIR__) . '/fixtures/envelope.v2/artifact.bin';

    $handle = fopen($path, 'rb');
    $envelope = ArtifactEnvelope::readHeader($handle);
    fclose($handle);

    $manifest = json_decode($envelope['manifest_bytes'], true, 512, JSON_THROW_ON_ERROR);

    $fingerprint = KeyFingerprint::forRecoveryKey($reference['keys'][$which]['public']);

    $recipient = null;

    foreach ($manifest['key_wrapping']['recipients'] as $candidate) {
        if (KeyFingerprint::matches($candidate['fingerprint'], $fingerprint)) {
            $recipient = $candidate;
        }
    }

    expect($recipient)->not->toBeNull();

    // Every active key gets its own copy of the artifact key. Losing one key must not cost the backup.
    $key = Sealing::unseal(
        $recipient['wrapped_key'],
        $reference['keys'][$which]['public'],
        $reference['keys'][$which]['secret'],
    );

    expect(base64_encode($key))->toBe($reference['artifact_key']);
})->with(['recovery_a', 'recovery_b']);

it('verifies the reference manifest against the site key that signed it', function (): void {
    $reference = fixture('envelope.v2/reference.json');
    $handle = fopen(dirname(__DIR__) . '/fixtures/envelope.v2/artifact.bin', 'rb');
    $envelope = ArtifactEnvelope::readHeader($handle);
    fclose($handle);

    expect(ArtifactEnvelope::verifyManifest(
        $envelope['manifest_bytes'],
        $envelope['signature'],
        $reference['keys']['site']['public'],
    ))->toBeTrue();

    // Pinned. If the signing prefix or the canonical bytes ever change, this stops verifying, and that
    // is a wire-format break rather than a refactor — bump the protocol version, do not regenerate the
    // fixture.
    expect($envelope['signature'])->toBe($reference['manifest_signature'])
        ->and(hash('sha256', $envelope['manifest_bytes']))->toBe($reference['manifest_sha256'])
        ->and($envelope['body_offset'])->toBe($reference['body_offset']);
});

it('embeds a manifest that satisfies its own schema', function (): void {
    $handle = fopen(dirname(__DIR__) . '/fixtures/envelope.v2/artifact.bin', 'rb');
    $envelope = ArtifactEnvelope::readHeader($handle);
    fclose($handle);

    $embedded = json_decode($envelope['manifest_bytes'], true, 512, JSON_THROW_ON_ERROR);

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($embedded))->toBe([])
        // The committed fixture and the bytes inside the file are the same document. A test that
        // validated only the fixture would pass while the artifact carried something else.
        ->and($embedded)->toBe(fixture('backup-manifest.v2/valid.json'));
});

it('tells a v2 artifact from a bare v1 stream', function (): void {
    $handle = fopen(dirname(__DIR__) . '/fixtures/envelope.v2/artifact.bin', 'rb');
    $opening = fread($handle, 8);
    fclose($handle);

    expect(ArtifactEnvelope::isEnvelope($opening))->toBeTrue();

    // A v1 artifact begins with a 24-byte random secret-stream header, so the chance of one opening
    // with this magic is 2^-48. Run enough of them that a systematic mistake would show.
    for ($i = 0; $i < 100; $i++) {
        $stream = fopen('php://memory', 'w+b');
        $input = fopen('php://memory', 'w+b');
        fwrite($input, 'a v1 artifact');
        rewind($input);
        ArtifactStream::encrypt($input, $stream, ArtifactStream::generateKey());
        rewind($stream);

        expect(ArtifactEnvelope::isEnvelope((string) fread($stream, 8)))->toBeFalse();

        fclose($stream);
        fclose($input);
    }
});

it('round trips a manifest byte for byte', function (): void {
    // The property the whole format depends on. The manifest is serialised once, by the connector, and
    // everything afterwards carries those exact bytes. Re-encoding JSON and hoping a signature survives
    // is how verification breaks a year later over how a slash was rendered.
    $site = Keys::generateKeypair();
    $manifestBytes = "{\"manifest_version\":\"backup-manifest.v2\",\"note\":\"  spacing\\/slashes  \"}";
    $signature = ArtifactEnvelope::signManifest($manifestBytes, $site['secret']);

    $stream = fopen('php://memory', 'w+b');
    $written = ArtifactEnvelope::write($stream, $manifestBytes, $signature);
    fwrite($stream, 'the encrypted body follows immediately');
    rewind($stream);

    $read = ArtifactEnvelope::readHeader($stream);

    expect($read['manifest_bytes'])->toBe($manifestBytes)
        ->and($read['signature'])->toBe($signature)
        ->and($read['body_offset'])->toBe($written)
        ->and(stream_get_contents($stream))->toBe('the encrypted body follows immediately');

    fclose($stream);
});

it('separates a manifest signature from a request signature', function (): void {
    // Without the domain prefix, a signature over a manifest would verify as a signature over a
    // canonical request that happened to have the same bytes, and vice versa.
    $site = Keys::generateKeypair();
    $bytes = '{"manifest_version":"backup-manifest.v2"}';

    $manifestSignature = ArtifactEnvelope::signManifest($bytes, $site['secret']);
    $plainSignature = Keys::sign($bytes, $site['secret']);

    expect($manifestSignature)->not->toBe($plainSignature)
        ->and(Keys::verify($bytes, $manifestSignature, $site['public']))->toBeFalse()
        ->and(ArtifactEnvelope::verifyManifest($bytes, $plainSignature, $site['public']))->toBeFalse();
});

it('refuses a manifest signed by a different site', function (): void {
    $mine = Keys::generateKeypair();
    $theirs = Keys::generateKeypair();
    $bytes = '{"manifest_version":"backup-manifest.v2"}';

    expect(ArtifactEnvelope::verifyManifest($bytes, ArtifactEnvelope::signManifest($bytes, $theirs['secret']), $mine['public']))
        ->toBeFalse();
});

it('refuses a manifest whose bytes were altered after signing', function (): void {
    $site = Keys::generateKeypair();
    $bytes = '{"manifest_version":"backup-manifest.v2","sequence":42}';
    $signature = ArtifactEnvelope::signManifest($bytes, $site['secret']);

    $altered = str_replace('42', '41', $bytes);

    expect(ArtifactEnvelope::verifyManifest($altered, $signature, $site['public']))->toBeFalse();
});

it('returns false rather than throwing on malformed signature material', function (string $signature): void {
    // The same reasoning as Keys::verify(). A caller checking an attacker-supplied signature should get
    // a plain no, not an exception that behaves differently from a bad signature and says which it was.
    expect(ArtifactEnvelope::verifyManifest('{}', $signature, Keys::generateKeypair()['public']))->toBeFalse();
})->with([
    'empty' => '',
    'not base64' => 'not base64!!',
    'too short' => base64_encode(str_repeat("\x01", 32)),
]);

it('refuses a file that does not begin like an artifact', function (): void {
    $stream = fopen('php://memory', 'w+b');
    fwrite($stream, 'PK' . str_repeat("\x00", 64));
    rewind($stream);

    expect(fn (): array => ArtifactEnvelope::readHeader($stream))->toThrow(ProtocolException::class);

    fclose($stream);
});

it('names a format version it cannot read rather than guessing', function (): void {
    $stream = fopen('php://memory', 'w+b');
    fwrite($stream, ArtifactEnvelope::MAGIC . chr(9) . chr(0) . pack('N', 2) . '{}' . pack('n', 64) . str_repeat("\x00", 64));
    rewind($stream);

    // A reader that quietly attempts a format it does not know is how a corrupt restore gets mistaken
    // for a corrupt backup.
    expect(fn (): array => ArtifactEnvelope::readHeader($stream))
        ->toThrow(ProtocolException::class, 'format version 9');

    fclose($stream);
});

it('ignores a minor version it does not know', function (): void {
    // That is what a minor version is for. A reader of this major version must tolerate additions.
    $site = Keys::generateKeypair();
    $bytes = '{"manifest_version":"backup-manifest.v2"}';
    $signature = base64_decode(ArtifactEnvelope::signManifest($bytes, $site['secret']), true);

    $stream = fopen('php://memory', 'w+b');
    fwrite($stream, ArtifactEnvelope::MAGIC
        . chr(ArtifactEnvelope::FORMAT_MAJOR)
        . chr(ArtifactEnvelope::FORMAT_MINOR + 7)
        . pack('N', strlen($bytes)) . $bytes
        . pack('n', 64) . $signature);
    rewind($stream);

    expect(ArtifactEnvelope::readHeader($stream)['manifest_bytes'])->toBe($bytes);

    fclose($stream);
});

it('refuses a declared manifest length outside the permitted range', function (int $length): void {
    // Checked before the read, not after. A declared length is an allocation request from somebody who
    // has not been authenticated yet.
    $stream = fopen('php://memory', 'w+b');
    fwrite($stream, ArtifactEnvelope::MAGIC
        . chr(ArtifactEnvelope::FORMAT_MAJOR)
        . chr(ArtifactEnvelope::FORMAT_MINOR)
        . pack('N', $length)
        . str_repeat('x', 128));
    rewind($stream);

    expect(fn (): array => ArtifactEnvelope::readHeader($stream))
        ->toThrow(ProtocolException::class, 'permitted range');

    fclose($stream);
})->with([
    'zero' => 0,
    'one byte over the ceiling' => ArtifactEnvelope::MAX_MANIFEST_BYTES + 1,
    'four gigabytes' => 4294967295,
]);

it('refuses to write a manifest outside the permitted range', function (string $manifest): void {
    $stream = fopen('php://memory', 'w+b');

    expect(fn (): int => ArtifactEnvelope::write($stream, $manifest, Keys::sign('x', Keys::generateKeypair()['secret'])))
        ->toThrow(ProtocolException::class);

    fclose($stream);
})->with([
    'empty' => '',
    'oversized' => str_repeat('x', ArtifactEnvelope::MAX_MANIFEST_BYTES + 1),
]);

it('refuses to write a signature of the wrong length', function (): void {
    $stream = fopen('php://memory', 'w+b');

    expect(fn (): int => ArtifactEnvelope::write($stream, '{}', base64_encode('short')))
        ->toThrow(ProtocolException::class);

    fclose($stream);
});

it('refuses an envelope that was cut short', function (int $keep): void {
    // Truncation is the failure that silently produces an unusable restore, so it has to be detected as
    // truncation rather than read as a shorter file.
    $bytes = fixtureBytes('envelope.v2/artifact.bin');

    $stream = fopen('php://memory', 'w+b');
    fwrite($stream, substr($bytes, 0, $keep));
    rewind($stream);

    expect(fn (): array => ArtifactEnvelope::readHeader($stream))->toThrow(ProtocolException::class);

    fclose($stream);
})->with([
    'nothing at all' => 0,
    'part of the magic' => 3,
    'the prefix only' => ArtifactEnvelope::PREFIX_BYTES,
    'part of the manifest' => 200,
    'stopping before the signature' => 1700,
]);

it('refuses a wrapped key belonging to a different artifact', function (): void {
    // A manifest lifted from one artifact and pasted onto another yields a key that does not open the
    // stream it now claims to describe. This is why the manifest does not need binding into the AEAD.
    $reference = fixture('envelope.v2/reference.json');

    $handle = fopen(dirname(__DIR__) . '/fixtures/envelope.v2/artifact.bin', 'rb');
    ArtifactEnvelope::readHeader($handle);

    $foreign = ArtifactStream::generateKey();
    $output = fopen('php://memory', 'w+b');

    expect(fn (): array => ArtifactStream::decrypt($handle, $output, $foreign))
        ->toThrow(ProtocolException::class);

    fclose($handle);
    fclose($output);

    expect($reference['artifact_key'])->not->toBe(base64_encode($foreign));
});

it('agrees with the constants the rest of the system reads', function (): void {
    expect(Protocol::MAX_BACKUP_MANIFEST_BYTES)->toBe(ArtifactEnvelope::MAX_MANIFEST_BYTES)
        ->and(ArtifactEnvelope::PREFIX_BYTES)->toBe(strlen(ArtifactEnvelope::MAGIC) + 1 + 1 + 4)
        ->and(Protocol::BACKUP_FORMAT_V2)->toBe('v2');
});
