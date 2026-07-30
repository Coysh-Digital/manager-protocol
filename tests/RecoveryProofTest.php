<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\KeyFingerprint;
use coyshdigital\managerprotocol\ProtocolException;
use coyshdigital\managerprotocol\RecoveryProof;
use coyshdigital\managerprotocol\Sealing;

/**
 * The ceremony that stops an unusable recovery key being enrolled.
 *
 * Almost nothing can be checked about a submitted X25519 public key — any 32 bytes is a valid one — so
 * the only meaningful test is whether somebody can demonstrate they hold the other half. The value is
 * less cryptographic than procedural: enrolling a key becomes a restore rehearsal.
 */
it('completes the ceremony end to end', function (): void {
    $recovery = Sealing::generateBoxKeypair();

    // Platform: seal a challenge, keep only the hash of the expected answer.
    $challenge = RecoveryProof::generateChallenge();
    $sealed = Sealing::seal((string) base64_decode($challenge, true), $recovery['public']);
    $expected = RecoveryProof::responseFor((string) base64_decode($challenge, true));
    $stored = hash('sha256', $expected);

    // Operator: open it offline and read back the code.
    $opened = Sealing::unseal($sealed, $recovery['public'], $recovery['secret']);
    $answer = RecoveryProof::responseFor($opened);

    expect(hash('sha256', $answer))->toBe($stored)
        ->and(RecoveryProof::matches($answer, $expected))->toBeTrue();
});

it('cannot be answered without the private key', function (): void {
    $recovery = Sealing::generateBoxKeypair();
    $impostor = Sealing::generateBoxKeypair();

    $challenge = (string) base64_decode(RecoveryProof::generateChallenge(), true);
    $sealed = Sealing::seal($challenge, $recovery['public']);

    // Holding the public key and the sealed blob is not enough, which is the point of a sealed box.
    expect(fn (): string => Sealing::unseal($sealed, $impostor['public'], $impostor['secret']))
        ->toThrow(ProtocolException::class);
});

it('gives a different answer for every challenge', function (): void {
    $seen = [];

    for ($i = 0; $i < 100; $i++) {
        $seen[] = RecoveryProof::responseFor((string) base64_decode(RecoveryProof::generateChallenge(), true));
    }

    expect(array_unique($seen))->toHaveCount(100);
});

it('reveals nothing about the challenge it came from', function (): void {
    // The platform stores the hash of the response, never the challenge. A response seen in transit
    // must not let somebody reconstruct what was sealed.
    $challenge = (string) base64_decode(RecoveryProof::generateChallenge(), true);
    $response = RecoveryProof::responseFor($challenge);

    expect($response)->not->toContain(base64_encode($challenge))
        ->and($response)->not->toContain(bin2hex($challenge))
        ->and(strlen($response))->toBeLessThan(strlen(bin2hex($challenge)));
});

it('looks exactly like a fingerprint so there is one format to learn', function (): void {
    $response = RecoveryProof::responseFor((string) base64_decode(RecoveryProof::generateChallenge(), true));

    expect($response)->toStartWith(KeyFingerprint::PROOF_PREFIX)
        ->and(strlen($response))->toBe(34)
        ->and(KeyFingerprint::isWellFormed($response))->toBeTrue()
        ->and($response)->toMatch('~^MGRP(-[0-9A-HJKMNP-TV-Z]{4}){6}\z~');
});

it('accepts an answer however the operator retyped it', function (callable $mangle): void {
    $expected = RecoveryProof::responseFor((string) base64_decode(RecoveryProof::generateChallenge(), true));

    expect(RecoveryProof::matches($mangle($expected), $expected))->toBeTrue();
})->with([
    'unchanged' => [fn (string $s): string => $s],
    'lowercase' => [fn (string $s): string => strtolower($s)],
    'spaces for hyphens' => [fn (string $s): string => str_replace('-', ' ', $s)],
    'run together' => [fn (string $s): string => str_replace('-', '', $s)],
    'pasted with whitespace' => [fn (string $s): string => "  {$s}\n"],
]);

it('rejects an answer that is merely close', function (): void {
    $expected = RecoveryProof::responseFor((string) base64_decode(RecoveryProof::generateChallenge(), true));
    $other = RecoveryProof::responseFor((string) base64_decode(RecoveryProof::generateChallenge(), true));

    expect(RecoveryProof::matches($other, $expected))->toBeFalse()
        ->and(RecoveryProof::matches(substr($expected, 0, 29), $expected))->toBeFalse()
        ->and(RecoveryProof::matches('', $expected))->toBeFalse();
});

it('is separated from a fingerprint over the same bytes', function (): void {
    // Without the domain string, a proof response and a fingerprint could collide, and an operator
    // pasting the wrong one would be told it was right.
    $bytes = str_repeat("\x2a", RecoveryProof::CHALLENGE_BYTES);

    $response = RecoveryProof::responseFor($bytes);
    $fingerprint = KeyFingerprint::forRecoveryKey(base64_encode(substr($bytes, 0, 32)));

    expect(substr($response, 5))->not->toBe(substr($fingerprint, 5));
});

it('refuses a challenge of the wrong length', function (int $length): void {
    expect(fn (): string => RecoveryProof::responseFor(str_repeat("\x01", $length)))
        ->toThrow(ProtocolException::class);
})->with(['empty' => 0, 'short' => 16, 'long' => 64]);

it('refuses to judge against a malformed expectation', function (): void {
    // Answering "no" to every submission would look exactly like an operator who cannot find their
    // key, and they would go looking in the wrong place.
    expect(fn (): bool => RecoveryProof::matches('MGRP-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C', 'nonsense'))
        ->toThrow(ProtocolException::class);
});
