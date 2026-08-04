<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\KeyFingerprint;
use coyshdigital\managerprotocol\Keys;
use coyshdigital\managerprotocol\ProtocolException;
use coyshdigital\managerprotocol\Sealing;

/**
 * A fingerprint is the only part of this system a person is expected to compare by eye.
 *
 * Everything about zero-knowledge backups rests on a customer being able to confirm that the key a
 * site is about to seal a database to is the key they hold. They do that by comparing a string in a
 * file on their laptop against a string in a configuration file on their server. So the properties
 * that matter here are not cryptographic subtleties - they are whether two renderings of the same key
 * always look the same, whether two different keys never do, and whether a human who retypes one
 * slightly differently still gets a match.
 */
it('renders a stable fingerprint for a known key', function (): void {
    $reference = fixture('envelope.v2/reference.json');

    // Pinned against the fixture rather than merely recomputed. If the domain string, the truncation
    // length or the alphabet ever changes, every fingerprint ever shown to a customer changes with it,
    // and that is a wire-format break rather than a refactor.
    expect(KeyFingerprint::forRecoveryKey($reference['keys']['recovery_a']['public']))
        ->toBe('MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C')
        ->and(KeyFingerprint::forRecoveryKey($reference['keys']['recovery_b']['public']))
        ->toBe('MGRK-139V-DYMJ-0TMZ-3M8B-7E0Q-NE1F')
        ->and(KeyFingerprint::forSiteKey($reference['keys']['site']['public']))
        ->toBe('MGRS-4GNX-3FDQ-K2MR-0B0S-ES6F-NRP1');
});

it('produces six groups of four and nothing ragged', function (): void {
    $fingerprint = KeyFingerprint::forRecoveryKey(Sealing::generateBoxKeypair()['public']);

    expect($fingerprint)->toMatch('~^MGRK(-[0-9A-HJKMNP-TV-Z]{4}){6}\z~')
        ->and(strlen($fingerprint))->toBe(34)
        ->and(KeyFingerprint::isWellFormed($fingerprint))->toBeTrue();
});

it('never uses a letter that can be misread as a digit', function (): void {
    // The whole reason for Crockford base32 rather than ordinary base32. Somebody reading a
    // fingerprint aloud must not have to say "I as in India, not one".
    for ($i = 0; $i < 200; $i++) {
        $body = substr(KeyFingerprint::forRecoveryKey(Sealing::generateBoxKeypair()['public']), 5);

        expect($body)->not->toContain('I')
            ->and($body)->not->toContain('L')
            ->and($body)->not->toContain('O')
            ->and($body)->not->toContain('U');
    }
});

it('gives a recovery key and a site key different fingerprints even from the same bytes', function (): void {
    // Both are 32-byte public keys, so without domain separation the same bytes read as an X25519 key
    // and as an Ed25519 key would fingerprint identically - and a customer comparing one against the
    // other would see a match that means nothing.
    $bytes = base64_encode(str_repeat("\x2a", 32));

    expect(KeyFingerprint::forRecoveryKey($bytes))->not->toBe(KeyFingerprint::forSiteKey($bytes));
});

it('never confuses the two kinds of fingerprint', function (): void {
    $recovery = KeyFingerprint::forRecoveryKey(Sealing::generateBoxKeypair()['public']);
    $site = KeyFingerprint::forSiteKey(Keys::generateKeypair()['public']);

    expect($recovery)->toStartWith(KeyFingerprint::RECOVERY_PREFIX)
        ->and($site)->toStartWith(KeyFingerprint::SITE_PREFIX)
        ->and(KeyFingerprint::matches($recovery, $site))->toBeFalse();
});

it('matches a fingerprint however somebody typed it', function (string $typed): void {
    // All of these are the same fingerprint. A customer copying one out of a PDF, or reading it off a
    // printout, must not be told their key is wrong because of a space.
    expect(KeyFingerprint::matches($typed, 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C'))->toBeTrue();
})->with([
    'canonical' => 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C',
    'lowercase' => 'mgrk-vtwg-mab4-amws-re3z-kmh7-ad5c',
    'spaces instead of hyphens' => 'MGRK VTWG MAB4 AMWS RE3Z KMH7 AD5C',
    'no separators at all' => 'MGRKVTWGMAB4AMWSRE3ZKMH7AD5C',
    'surrounding whitespace' => "  MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C\n",
    'wrapped across lines' => "MGRK-VTWG-MAB4-AMWS-\nRE3Z-KMH7-AD5C",
]);

it('reads a mistyped letter as the digit it was meant to be', function (): void {
    // Crockford's decoding rules exist for exactly this. A fingerprint containing 0 typed as O, or 1
    // typed as I or L, is the same fingerprint.
    $canonical = 'MGRK-139V-DYMJ-0TMZ-3M8B-7E0Q-NE1F';

    expect(KeyFingerprint::matches('MGRK-I39V-DYMJ-OTMZ-3M8B-7EOQ-NEIF', $canonical))->toBeTrue()
        ->and(KeyFingerprint::matches('MGRK-L39V-DYMJ-OTMZ-3M8B-7EOQ-NELF', $canonical))->toBeTrue();
});

it('does not treat U as a near miss', function (): void {
    // U is excluded from the alphabet rather than aliased onto something, so a U is a genuine error
    // rather than a character that needs interpreting.
    expect(KeyFingerprint::matches('MGRK-U39V-DYMJ-0TMZ-3M8B-7E0Q-NE1F', 'MGRK-139V-DYMJ-0TMZ-3M8B-7E0Q-NE1F'))
        ->toBeFalse();
});

it('does not quietly reshape a fingerprint of the wrong length', function (): void {
    // A truncated fingerprint must fail the comparison it is about to be used in, not be padded into
    // something that might pass one.
    expect(KeyFingerprint::normalise('MGRK-139V-DYMJ'))->toBe('MGRK139VDYMJ')
        ->and(KeyFingerprint::isWellFormed(KeyFingerprint::normalise('MGRK-139V-DYMJ')))->toBeFalse();
});

it('rejects a key that is not the right kind of key', function (string $key): void {
    expect(fn (): string => KeyFingerprint::forRecoveryKey($key))->toThrow(ProtocolException::class);
})->with([
    'empty' => '',
    'not base64' => 'not base64 at all!!',
    'an Ed25519 secret key' => Keys::generateKeypair()['secret'],
    'too short' => base64_encode(str_repeat("\x01", 31)),
    'too long' => base64_encode(str_repeat("\x01", 33)),
]);

it('never repeats the rejected key back', function (): void {
    // A malformed key is usually a paste error, and echoing it into an exception is how key material
    // reaches a log. Even a public key identifies an organisation.
    $key = base64_encode('this-is-not-a-key-but-it-is-recognisable');

    try {
        KeyFingerprint::forRecoveryKey($key);
    } catch (ProtocolException $e) {
        expect($e->getMessage())->not->toContain($key)
            ->and($e->getMessage())->not->toContain('recognisable');

        return;
    }

    $this->fail('The malformed key was accepted.');
});

it('refuses a fingerprint with a prefix it did not issue', function (string $fingerprint): void {
    expect(KeyFingerprint::isWellFormed($fingerprint))->toBeFalse();
})->with([
    'unknown prefix' => 'MGRX-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C',
    'no prefix' => 'VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C',
    'too few groups' => 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7',
    'too many groups' => 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C-0000',
    'excluded letter' => 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-ADIC',
    'trailing newline' => "MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C\n",
]);
