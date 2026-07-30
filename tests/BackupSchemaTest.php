<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The backup schema is the third data-minimisation boundary, and the one that matters most.
 *
 * An artifact declaration describes a backup. It must never contain one, and it must never contain
 * the means of taking another: no credentials, no connection string, no path on the site's disk. The
 * platform needs enough to store the bytes, verify they arrived intact and eventually decrypt them.
 * Everything beyond that is collection for its own sake.
 */
it('accepts a realistic artifact declaration', function (): void {
    expect(SchemaValidator::forSchema('backup.v1')->validate(fixture('backup.v1/valid.json')))
        ->toBe([]);
});

it('rejects credentials, connection details, paths and content samples', function (): void {
    $errors = SchemaValidator::forSchema('backup.v1')->validate(fixture('backup.v1/forbidden-content.json'));

    $joined = implode(' ', $errors);

    // Every one of these is rejected rather than stripped. A connector sending them has misunderstood
    // the boundary, and quietly dropping them would hide that until the next field was added.
    expect($joined)->toContain('database_password')
        ->and($joined)->toContain('dsn')
        ->and($joined)->toContain('local_path')
        ->and($joined)->toContain('tables')
        ->and($joined)->toContain('sample_rows')
        ->and($joined)->toContain('admin_email');
});

it('requires both checksums', function (string $missing): void {
    $declaration = fixture('backup.v1/valid.json');
    unset($declaration['artifact'][$missing]);

    // Neither hash is optional. Without the ciphertext hash the platform cannot tell a truncated
    // upload from a complete one; without the plaintext hash nobody can tell a decrypted artifact
    // from a plausible-looking corruption of it.
    expect(SchemaValidator::forSchema('backup.v1')->validate($declaration))->not->toBe([]);
})->with(['ciphertext_sha256', 'plaintext_sha256']);

it('rejects a checksum that is not a sha-256', function (string $value): void {
    $declaration = fixture('backup.v1/valid.json');
    $declaration['artifact']['ciphertext_sha256'] = $value;

    expect(SchemaValidator::forSchema('backup.v1')->validate($declaration))->not->toBe([]);
})->with([
    'too short' => 'abc123',
    'not hex' => 'zzzz1b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8',
    'uppercase' => '9F2C1B3A4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8',
    'empty' => '',
]);

it('rejects an unknown database engine', function (): void {
    $declaration = fixture('backup.v1/valid.json');
    $declaration['artifact']['engine'] = 'sqlite';

    expect(SchemaValidator::forSchema('backup.v1')->validate($declaration))->not->toBe([]);
});

it('rejects a zero-length artifact', function (): void {
    $declaration = fixture('backup.v1/valid.json');
    $declaration['artifact']['ciphertext_bytes'] = 0;

    // A backup of nothing is a failure that produced a file, and storing it would let it satisfy a
    // retention policy while protecting nobody.
    expect(SchemaValidator::forSchema('backup.v1')->validate($declaration))->not->toBe([]);
});
