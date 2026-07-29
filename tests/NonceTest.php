<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\Nonce;
use coyshdigital\managerprotocol\Protocol;

it('generates unique, well-formed nonces', function (): void {
    $nonces = array_map(fn () => Nonce::generate(), range(1, 500));

    expect(array_unique($nonces))->toHaveCount(500);

    foreach ($nonces as $nonce) {
        expect(Nonce::isValid($nonce))->toBeTrue();
    }
});

it('rejects malformed nonces before they reach the replay store', function (string $nonce): void {
    // A nonce becomes part of a cache key, so it is validated for shape first.
    expect(Nonce::isValid($nonce))->toBeFalse();
})->with([
    'empty' => [''],
    'too short' => ['abc'],
    'too long' => [str_repeat('a', 64)],
    'path traversal' => ['../../etc/passwd'],
    'key separator' => ['aaaaaaaaaa:aaaaaaaaaaa'],
    'padded base64' => ['Zm9vYmFyYmF6cXV4MTIz=='],
]);

it('generates recognisable, unique enrolment codes', function (): void {
    $codes = array_map(fn () => Nonce::generateEnrolmentCode(), range(1, 200));

    expect(array_unique($codes))->toHaveCount(200);

    foreach ($codes as $code) {
        // The prefix means a leaked code is recognisable in a log or a paste.
        expect($code)->toStartWith(Protocol::ENROLMENT_CODE_PREFIX)
            ->and(Nonce::isValidEnrolmentCode($code))->toBeTrue();
    }
});

it('rejects malformed enrolment codes without touching the database', function (string $code): void {
    expect(Nonce::isValidEnrolmentCode($code))->toBeFalse();
})->with([
    'empty' => [''],
    'no prefix' => ['Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWpr'],
    'wrong prefix' => ['mgr_pair_Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWpr'],
    'truncated' => ['mgr_enrol_abc'],
    'sql-ish' => ["mgr_enrol_' OR 1=1 --"],
]);

it('hashes enrolment codes deterministically and without the plaintext', function (): void {
    $code = Nonce::generateEnrolmentCode();
    $hash = Nonce::hashEnrolmentCode($code);

    expect($hash)->toBe(Nonce::hashEnrolmentCode($code))
        ->and($hash)->toHaveLength(64)
        ->and($hash)->not->toContain($code)
        ->and(Nonce::hashEnrolmentCode(Nonce::generateEnrolmentCode()))->not->toBe($hash);
});

it('carries enough entropy that guessing is not the weak link', function (): void {
    // 256 bits from the CSPRNG. This is why a plain SHA-256 is the right store hash: there is no
    // dictionary to slow an attacker down to, and consuming the code must stay a single atomic
    // indexed statement.
    expect(Protocol::ENROLMENT_CODE_BYTES)->toBeGreaterThanOrEqual(32)
        ->and(Protocol::NONCE_BYTES)->toBeGreaterThanOrEqual(16);
});
