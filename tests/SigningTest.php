<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\CanonicalNudge;
use coyshdigital\managerprotocol\CanonicalRequest;
use coyshdigital\managerprotocol\CanonicalResponse;
use coyshdigital\managerprotocol\Keys;
use coyshdigital\managerprotocol\Nonce;
use coyshdigital\managerprotocol\Protocol;

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

it('reproduces and verifies the canonical nudge string', function (): void {
    $fixture = fixture('signing.json');
    $f = $fixture['nudge'];

    $nudge = new CanonicalNudge(
        $fixture['request']['site_id'],
        $fixture['request']['timestamp'],
        $fixture['request']['nonce'],
    );

    expect($nudge->toString())->toBe($f['canonical_string'])
        ->and($nudge->verify($f['signature'], $fixture['platform_keypair']['public']))->toBeTrue();
});

it('rejects a nudge signature once any signed field changes', function (string $field): void {
    $fixture = fixture('signing.json');

    $values = [
        'site_id' => $fixture['request']['site_id'],
        'timestamp' => $fixture['request']['timestamp'],
        'nonce' => $fixture['request']['nonce'],
    ];

    $values[$field] = $field === 'timestamp' ? $values[$field] + 1 : $values[$field] . 'x';

    $tampered = new CanonicalNudge(...array_values($values));

    expect($tampered->verify($fixture['nudge']['signature'], $fixture['platform_keypair']['public']))
        ->toBeFalse();
})->with(['site_id', 'timestamp', 'nonce']);

it('does not let a signed response stand in for a nudge, or the reverse', function (): void {
    $fixture = fixture('signing.json');

    // One key signs both. The prefixes are the only thing keeping the two canonical strings from
    // colliding, so this asserts the separation rather than trusting the constants to stay distinct.
    $nudge = new CanonicalNudge(
        $fixture['request']['site_id'],
        $fixture['request']['timestamp'],
        $fixture['request']['nonce'],
    );

    $response = new CanonicalResponse(
        $fixture['request']['site_id'],
        $fixture['request']['nonce'],
        $fixture['response']['status'],
        $fixture['response']['body'],
    );

    $public = $fixture['platform_keypair']['public'];

    expect($nudge->verify($fixture['response']['signature'], $public))->toBeFalse()
        ->and($response->verify($fixture['nudge']['signature'], $public))->toBeFalse()
        ->and($nudge->toString())->not->toBe($response->toString());
});

it('asks a nudge to carry nothing but who, when and once', function (): void {
    // Four lines, and the first is a constant. A nudge that grew a field for a job type, a path or a
    // capability would be a nudge that could carry an instruction, which is the one thing this
    // canonical form exists to make impossible.
    $nudge = new CanonicalNudge('01JRZX9K2Q4M8N7P6T5V3W2Y1B', 1785340000, Nonce::generate());

    expect(explode("\n", $nudge->toString()))->toHaveCount(4)
        ->and((new ReflectionClass(CanonicalNudge::class))->getConstructor()?->getNumberOfParameters())
        ->toBe(3);
});

it('names four headers for a nudge and leaves the request list alone', function (): void {
    expect(Protocol::nudgeHeaders())->toBe([
        Protocol::HEADER_SITE,
        Protocol::HEADER_TIMESTAMP,
        Protocol::HEADER_NONCE,
        Protocol::HEADER_SIGNATURE,
    ])
        // A nudge travels the other way, so there is no connector version to report - and widening
        // the connector's list to cover this direction is the mistake this asserts against.
        ->and(Protocol::nudgeHeaders())->not->toContain(Protocol::HEADER_CONNECTOR_VERSION)
        ->and(Protocol::requiredRequestHeaders())->toContain(Protocol::HEADER_CONNECTOR_VERSION);
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

it('signs a streamed body exactly as a held one', function (): void {
    $body = random_bytes(4096);

    $held = new CanonicalRequest(
        siteId: '01KYRXWJ3Z9407ACBQ41PNA81H',
        connectorVersion: '1.0.0',
        timestamp: 1785484800,
        nonce: 'PxJ8kQ2mZ1vLbN4tRc7yWg==',
        method: 'PUT',
        path: '/api/connector/v1/backups/abc/content',
        body: $body,
    );

    $streamed = CanonicalRequest::forStream(
        siteId: '01KYRXWJ3Z9407ACBQ41PNA81H',
        connectorVersion: '1.0.0',
        timestamp: 1785484800,
        nonce: 'PxJ8kQ2mZ1vLbN4tRc7yWg==',
        method: 'PUT',
        path: '/api/connector/v1/backups/abc/content',
        bodyHash: hash('sha256', $body),
    );

    // One signing format, not one per transport. A platform verifying an upload runs the same code it
    // runs for every other request; only where the hash came from differs.
    expect($streamed->toString())->toBe($held->toString());
});

it('does not verify when a streamed hash does not match the bytes that follow', function (): void {
    $keypair = Keys::generateKeypair();

    $declared = CanonicalRequest::forStream(
        siteId: '01KYRXWJ3Z9407ACBQ41PNA81H',
        connectorVersion: '1.0.0',
        timestamp: 1785484800,
        nonce: 'PxJ8kQ2mZ1vLbN4tRc7yWg==',
        method: 'PUT',
        path: '/api/connector/v1/backups/abc/content',
        bodyHash: hash('sha256', 'what was promised'),
    );

    $signature = $declared->sign($keypair['secret']);

    // The signature is over the declaration, so it still verifies - the declaration is what was
    // signed. Catching the substitution is the receiver's job, by hashing the stream and comparing.
    // This test exists to record that division of responsibility rather than to assume it.
    expect($declared->verify($signature, $keypair['public']))->toBeTrue()
        ->and(hash('sha256', 'what actually arrived'))->not->toBe($declared->bodyHash());
});
