<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\Protocol;
use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The v2 backup schemas, which are where the zero-knowledge claim is either true or decorative.
 *
 * Two documents, and the split is the point. The **declaration** is what a connector sends before it
 * uploads; the platform validates it, stores what it says, and cannot act on any of it. The
 * **manifest** is what travels inside the artifact file, and it is the thing a customer reads a year
 * later with only a private key. Both are allowlists.
 *
 * What must not be in either: anything the platform could use to open a backup, and anything that
 * describes what is inside one. v1 already refused credentials, connection strings, table names and
 * content samples. v2 refuses one more thing - a key the platform could use - and the absence of
 * `sealed_key` from this schema is the whole difference between the two formats.
 */
it('accepts a realistic v2 declaration', function (): void {
    expect(SchemaValidator::forSchema('backup.v2')->validate(fixture('backup.v2/valid.json')))
        ->toBe([]);
});

it('carries no key the platform could use', function (): void {
    $declaration = fixture('backup.v2/valid.json');

    // The difference between v1 and v2, expressed as an assertion rather than a comment. v1 carried
    // `sealed_key`, sealed to the platform's own box key, and the platform opened it on arrival.
    $keys = array_keys($declaration);

    expect($keys)->not->toContain('sealed_key')
        ->and($keys)->not->toContain('wrapped_key')
        ->and($keys)->not->toContain('platform_key');

    $schema = json_decode(
        (string) file_get_contents(SchemaValidator::schemaDirectory() . '/backup.v2.json'),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    // And the schema would refuse one if a connector sent it, rather than merely not requiring it.
    expect($schema['additionalProperties'])->toBeFalse()
        ->and(array_keys($schema['properties']))->not->toContain('sealed_key');
});

it('rejects a field the schema does not name', function (): void {
    $errors = SchemaValidator::forSchema('backup.v2')->validate(fixture('backup.v2/unknown-field.json'));

    // `storage_endpoint` models the specific mistake worth catching: a destination arriving as data.
    // Rejected rather than stripped, so the drift is visible the moment it appears.
    expect(implode(' ', $errors))->toContain('storage_endpoint');
});

it('rejects credentials, connection details, paths and content samples', function (): void {
    $errors = implode(' ', SchemaValidator::forSchema('backup.v2')->validate(fixture('backup.v2/forbidden-content.json')));

    expect($errors)->toContain('database_password')
        ->and($errors)->toContain('dsn')
        ->and($errors)->toContain('local_path')
        ->and($errors)->toContain('tables')
        ->and($errors)->toContain('sample_rows')
        ->and($errors)->toContain('admin_email');
});

it('never echoes a rejected value back', function (): void {
    // The reason for it is the same as everywhere else in this validator: an error message is a place
    // values go to be logged. `hunter2` is in the forbidden fixture precisely so this can look for it.
    $errors = implode(' ', SchemaValidator::forSchema('backup.v2')->validate(fixture('backup.v2/forbidden-content.json')));

    expect($errors)->not->toContain('hunter2')
        ->and($errors)->not->toContain('10.0.0.4')
        ->and($errors)->not->toContain('someone@example.invalid');
});

it('requires everything a platform needs to verify an upload it cannot read', function (string $field): void {
    $declaration = fixture('backup.v2/valid.json');
    unset($declaration[$field]);

    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
})->with([
    'schema_version',
    'job_id',
    'manifest_b64',
    'manifest_sha256',
    'manifest_signature',
    'artifact_sha256',
    'artifact_bytes',
]);

it('pins the schema version rather than accepting any version string', function (): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration['schema_version'] = 'backup.v3';

    // A document claiming a version this build does not implement is refused, not interpreted.
    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
});

it('rejects a job id that is not a ulid', function (string $value): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration['job_id'] = $value;

    // v1 expressed this as minLength/maxLength, and this validator implements neither minLength nor
    // any length floor - so `backup.v1.json` has always carried a constraint that enforced nothing.
    // v2 says it as a pattern, which this validator does implement.
    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
})->with([
    'empty' => '',
    'one character' => 'X',
    'lowercase' => '01jrzx9k2q4m8n7p6t5v3w2y1b',
    'contains an excluded letter' => '01JRZX9K2Q4M8N7P6T5V3W2YIB',
    'too long' => '01JRZX9K2Q4M8N7P6T5V3W2Y1BB',
    'trailing newline' => "01JRZX9K2Q4M8N7P6T5V3W2Y1B\n",
]);

it('rejects a checksum that is not a sha-256', function (string $field, string $value): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration[$field] = $value;

    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
})->with([
    ['artifact_sha256', 'abc123'],
    ['artifact_sha256', '9F2C1B3A4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4C5D6E7F8'],
    // The v1 patterns end in `$`, which PCRE matches before a trailing newline. v2 uses `\z`.
    ['artifact_sha256', "9f2c1b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8\n"],
    ['manifest_sha256', 'not a hash'],
]);

it('rejects an artifact larger than the protocol permits', function (): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration['artifact_bytes'] = Protocol::MAX_ARTIFACT_BYTES + 1;

    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
});

it('rejects an artifact too small to contain an envelope', function (): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration['artifact_bytes'] = 12;

    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
});

it('rejects an upload mode outside the closed set', function (): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration['upload_mode'] = 'ftp';

    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
});

/*
|-------------------------------------------------------------------------------------------------
| The manifest
|-------------------------------------------------------------------------------------------------
*/

it('accepts the reference manifest', function (): void {
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate(fixture('backup-manifest.v2/valid.json')))
        ->toBe([]);
});

it('rejects a manifest field the schema does not name', function (): void {
    $errors = SchemaValidator::forSchema('backup-manifest.v2')
        ->validate(fixture('backup-manifest.v2/unknown-field.json'));

    expect(implode(' ', $errors))->toContain('database_host');
});

it('rejects a manifest carrying secret key material or a description of the data', function (): void {
    $errors = implode(
        ' ',
        SchemaValidator::forSchema('backup-manifest.v2')->validate(fixture('backup-manifest.v2/forbidden-content.json')),
    );

    // A recipient entry holds a wrapped key and a public key. A secret key next to them would defeat
    // the entire arrangement, and it is exactly the field somebody would add "for convenience".
    expect($errors)->toContain('secret_key')
        ->and($errors)->toContain('private_key')
        ->and($errors)->toContain('dsn')
        ->and($errors)->toContain('database_password')
        ->and($errors)->toContain('local_path')
        ->and($errors)->toContain('tables')
        ->and($errors)->toContain('sample_rows')
        ->and($errors)->not->toContain('hunter2');
});

it('requires everything needed to decrypt offline', function (string $field): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    unset($manifest[$field]);

    // The test for whether the manifest is genuinely self-describing. Every one of these missing makes
    // the file unopenable, or unattributable, without asking the platform something.
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with([
    'manifest_version',
    'artifact_id',
    'site_id',
    'site_key_fingerprint',
    'taken_at',
    'sequence',
    'encryption',
    'key_wrapping',
    'integrity',
]);

it('requires both checksums and both sizes', function (string $field): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    unset($manifest['integrity'][$field]);

    // Neither hash is optional. Without the ciphertext hash a reader cannot tell a truncated file from
    // a complete one; without the plaintext hash nobody can tell a decrypted artifact from a
    // plausible-looking corruption of it.
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with(['plaintext_sha256', 'ciphertext_sha256', 'plaintext_bytes', 'ciphertext_bytes']);

it('pins the chunk size to the one this protocol frames', function (int $chunk): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['encryption']['chunk_bytes'] = $chunk;

    // A reader has to frame the stream the way the writer did. Accepting a different size would produce
    // a file this build stores and cannot read back.
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with([
    'smaller' => 4096,
    'larger' => 2097152,
    'off by one' => Protocol::ARTIFACT_CHUNK_BYTES + 1,
]);

it('accepts only the encryption scheme this protocol implements', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['encryption']['scheme'] = 'aes-256-gcm-v1';

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
});

it('accepts only the key wrapping algorithm this protocol implements', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['key_wrapping']['algorithm'] = 'rsa-oaep-v1';

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
});

it('bounds how many recipients one artifact may be sealed to', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $one = $manifest['key_wrapping']['recipients'][0];

    // Every recipient is another copy of the key that opens this backup, so the list is bounded rather
    // than open.
    $manifest['key_wrapping']['recipients'] = array_fill(0, Protocol::MAX_BACKUP_RECIPIENTS, $one);
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->toBe([]);

    $manifest['key_wrapping']['recipients'] = array_fill(0, Protocol::MAX_BACKUP_RECIPIENTS + 1, $one);
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
});

it('does not pretend to enforce a minimum recipient count', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['key_wrapping']['recipients'] = [];

    // This validator implements no minItems, so an empty list passes the schema. That is not an
    // oversight to be papered over here - it is why "at least one recipient" is a check in the
    // platform and the connector, and why the schema description says so out loud. A schema that
    // appeared to guarantee it would be the same trap as v1's unenforced minLength.
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->toBe([]);
});

it('rejects a recipient missing any of the three things needed to use it', function (string $field): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    unset($manifest['key_wrapping']['recipients'][0][$field]);

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with(['fingerprint', 'public_key', 'wrapped_key']);

it('rejects key material of the wrong length', function (string $field, string $value): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['key_wrapping']['recipients'][0][$field] = $value;

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with([
    'public key too short' => ['public_key', base64_encode(str_repeat("\x01", 31))],
    'public key too long' => ['public_key', base64_encode(str_repeat("\x01", 33))],
    'public key not base64' => ['public_key', 'not base64 at all!!!!!!!!!!!!!!!!!!!!!!!!!!'],
    'wrapped key too short' => ['wrapped_key', base64_encode(str_repeat("\x01", 79))],
    'wrapped key too long' => ['wrapped_key', base64_encode(str_repeat("\x01", 81))],
]);

it('rejects a fingerprint that is not one this protocol issues', function (string $value): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['key_wrapping']['recipients'][0]['fingerprint'] = $value;

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with([
    'a site fingerprint where a recovery one belongs' => 'MGRS-4GNX-3FDQ-K2MR-0B0S-ES6F-NRP1',
    'hex instead' => 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
    'excluded letter' => 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-ADIC',
    'lowercase' => 'mgrk-vtwg-mab4-amws-re3z-kmh7-ad5c',
]);

it('requires the manifest to name the site key that signed it', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['site_key_fingerprint'] = 'MGRK-VTWG-MAB4-AMWS-RE3Z-KMH7-AD5C';

    // A recovery fingerprint here would be a category error, and the prefixes are what catch it.
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
});

it('rejects a timestamp outside a plausible range', function (int $value): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['taken_at'] = $value;

    // A site with a wrong clock should be visible rather than sorted into the wrong decade.
    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with(['epoch' => 0, 'before this product existed' => 1000000000, 'far future' => 5000000000]);

it('rejects a boolean where an integer belongs', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['sequence'] = true;

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
});

it('rejects an unknown database engine', function (): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['source']['engine'] = 'sqlite';

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
});

/*
|-------------------------------------------------------------------------------------------------
| Progress
|-------------------------------------------------------------------------------------------------
*/

it('accepts a progress report', function (): void {
    expect(SchemaValidator::forSchema('backup-progress.v1')->validate(fixture('backup-progress.v1/valid.json')))
        ->toBe([]);
});

it('refuses a progress report that says what it is working on', function (): void {
    $errors = implode(
        ' ',
        SchemaValidator::forSchema('backup-progress.v1')->validate(fixture('backup-progress.v1/forbidden-content.json')),
    );

    // The temptation with a progress report is to attach what is being worked on. A table name is a
    // description of the site's schema; a path is a description of its filesystem; a byte count as the
    // dump grows leaks the size of the database in real time. None of them belong in a heading that
    // looks this harmless.
    expect($errors)->toContain('local_path')
        ->and($errors)->toContain('bytes_written')
        ->and($errors)->toContain('current_table')
        ->and($errors)->toContain('dsn');
});

it('accepts only a stage from the closed list', function (string $stage): void {
    $report = fixture('backup-progress.v1/valid.json');
    $report['stage'] = $stage;

    expect(SchemaValidator::forSchema('backup-progress.v1')->validate($report))->not->toBe([]);
})->with(['restore', 'delete', 'DUMP', '']);

it('reserves the stages a connector does not send yet', function (string $stage): void {
    // Declared now so a later connector can start sending them without a platform change.
    $report = fixture('backup-progress.v1/valid.json');
    $report['stage'] = $stage;

    expect(SchemaValidator::forSchema('backup-progress.v1')->validate($report))->toBe([]);
})->with(['dump', 'encrypt', 'upload']);
