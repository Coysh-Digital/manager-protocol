<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\CanonicalRequest;
use coyshdigital\managerprotocol\CanonicalResponse;
use coyshdigital\managerprotocol\Keys;
use coyshdigital\managerprotocol\Nonce;

/**
 * The canonical string and the signatures over it are the contract between two separately
 * versioned codebases. These assertions are against committed fixtures on purpose: if they start
 * failing, the wire format has changed and the protocol version has to move with it.
 */
it('reproduces the canonical request string byte for byte', function (): void {
    $f = fixture('signing.json')['request'];

    $request = new CanonicalRequest(
        $f['site_id'],
        $f['connector_version'],
        $f['timestamp'],
        $f['nonce'],
        $f['method'],
        $f['path'],
        $f['body'],
    );

    expect($request->toString())->toBe($f['canonical_string'])
        ->and($request->bodyHash())->toBe($f['body_sha256']);
});

it('verifies the fixture request signature', function (): void {
    $fixture = fixture('signing.json');
    $f = $fixture['request'];

    $request = new CanonicalRequest(
        $f['site_id'],
        $f['connector_version'],
        $f['timestamp'],
        $f['nonce'],
        $f['method'],
        $f['path'],
        $f['body'],
    );

    expect($request->verify($f['signature'], $fixture['platform_keypair']['public']))->toBeTrue();
});

it('reproduces and verifies the canonical response string', function (): void {
    $fixture = fixture('signing.json');
    $f = $fixture['response'];

    $response = new CanonicalResponse(
        $fixture['request']['site_id'],
        $fixture['request']['nonce'],
        $f['status'],
        $f['body'],
    );

    expect($response->toString())->toBe($f['canonical_string'])
        ->and($response->verify($f['signature'], $fixture['platform_keypair']['public']))->toBeTrue();
});

it('rejects a signature once any signed field changes', function (string $field): void {
    $fixture = fixture('signing.json');
    $f = $fixture['request'];

    $values = [
        'site_id' => $f['site_id'],
        'connector_version' => $f['connector_version'],
        'timestamp' => $f['timestamp'],
        'nonce' => $f['nonce'],
        'method' => $f['method'],
        'path' => $f['path'],
        'body' => $f['body'],
    ];

    $values[$field] = $field === 'timestamp' ? $values[$field] + 1 : $values[$field] . 'x';

    $tampered = new CanonicalRequest(...array_values($values));

    expect($tampered->verify($f['signature'], $fixture['platform_keypair']['public']))->toBeFalse();
})->with(['site_id', 'connector_version', 'timestamp', 'nonce', 'method', 'path', 'body']);

it('binds a response signature to the request nonce', function (): void {
    $fixture = fixture('signing.json');
    $f = $fixture['response'];

    // Same response, replayed against a different request. It must not verify, or a captured
    // response could be replayed at the connector against later traffic.
    $replayed = new CanonicalResponse(
        $fixture['request']['site_id'],
        Nonce::generate(),
        $f['status'],
        $f['body'],
    );

    expect($replayed->verify($f['signature'], $fixture['platform_keypair']['public']))->toBeFalse();
});

it('round-trips a freshly generated keypair', function (): void {
    $keypair = Keys::generateKeypair();

    $signature = Keys::sign('hello', $keypair['secret']);

    expect(Keys::verify('hello', $signature, $keypair['public']))->toBeTrue()
        ->and(Keys::verify('hello there', $signature, $keypair['public']))->toBeFalse()
        ->and(Keys::isValidPublicKey($keypair['public']))->toBeTrue();
});

it('returns false rather than throwing on malformed key material', function (string $signature, string $publicKey): void {
    // A caller verifying attacker-supplied input should get a plain "no". An exception here would
    // behave differently from a bad signature and leak which of the two it was.
    expect(Keys::verify('hello', $signature, $publicKey))->toBeFalse();
})->with([
    'not base64' => ['!!!!', 'wtTQtctkVi1Kxeol29zmBxJZiTP35EF6A51LAb12sRs='],
    'wrong signature length' => ['aGVsbG8=', 'wtTQtctkVi1Kxeol29zmBxJZiTP35EF6A51LAb12sRs='],
    'wrong key length' => [str_repeat('A', 88), 'aGVsbG8='],
    'empty' => ['', ''],
]);

it('canonicalises paths and sorts query parameters', function (): void {
    foreach (fixture('signing.json')['canonical_path_cases'] as $case) {
        expect(CanonicalRequest::canonicalPath($case['path'], $case['query']))->toBe($case['expected']);
    }
});

it('produces one canonical form regardless of query ordering', function (): void {
    $a = CanonicalRequest::canonicalPath('/jobs', ['b' => '2', 'a' => '1']);
    $b = CanonicalRequest::canonicalPath('/jobs', ['a' => '1', 'b' => '2']);

    expect($a)->toBe($b);
});
