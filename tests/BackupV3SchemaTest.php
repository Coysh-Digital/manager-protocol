<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\ArtifactEnvelope;
use coyshdigital\managerprotocol\Protocol;
use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The v3 backup schemas, which exist for one reason: a size.
 *
 * v2 wrote a 2 GiB ceiling into `artifact_bytes` and described it as "the platform's artifact limit".
 * It was not the platform's limit - it was the protocol's, and a platform could not change it. On the
 * hosted edition, which owns the storage and bills for it, that number refused four nightly backups on
 * a live site whose database had grown; on a self-hosted install the corresponding setting lives in a
 * config file on the customer's own server, which most sites do not have. A ceiling nobody can reach
 * is not a policy, it is a wall.
 *
 * So v3 removes the maximum here and leaves the floor. Where the ceiling went is the substance of the
 * change: to the platform's own configuration, checked by the platform, named in the refusal.
 *
 * Everything else is v2. Same envelope, same signing prefix, same encryption, same manifest structure
 * - which is why {@see it('reads a v3 manifest signature with the v2 rule')} matters more than it
 * looks: if the envelope had moved, every artifact ever written would need a new reader.
 */
it('accepts a realistic v3 declaration', function (): void {
    expect(SchemaValidator::forSchema('backup.v3')->validate(fixture('backup.v3/valid.json')))
        ->toBe([]);
});

it('accepts an artifact far larger than v2 permitted', function (): void {
    $declaration = fixture('backup.v3/valid.json');

    // The fixture is already a twenty-gigabyte artifact, so this asserts the thing that was broken
    // rather than a hypothetical: the exact declaration the console refused is now accepted.
    expect($declaration['artifact_bytes'])->toBeGreaterThan(Protocol::MAX_ARTIFACT_BYTES)
        ->and(SchemaValidator::forSchema('backup.v3')->validate($declaration))->toBe([]);

    $declaration['artifact_bytes'] = Protocol::MAX_ARTIFACT_BYTES * 16;

    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->toBe([]);
});

it('leaves v2 refusing exactly what it always refused', function (): void {
    $declaration = fixture('backup.v2/valid.json');
    $declaration['artifact_bytes'] = Protocol::MAX_ARTIFACT_BYTES + 1;

    // Add-only, stated as a test. A published schema does not change meaning because a newer one
    // disagrees with it, and a connector still sending v2 must get v2's answer.
    expect(SchemaValidator::forSchema('backup.v2')->validate($declaration))->not->toBe([]);
});

it('still refuses an artifact too small to contain an envelope', function (int $bytes): void {
    $declaration = fixture('backup.v3/valid.json');
    $declaration['artifact_bytes'] = $bytes;

    // Removing the ceiling did not remove the floor. A declaration below this describes something
    // that could not be an artifact at all, whatever a platform has configured.
    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->not->toBe([]);
})->with([
    'zero' => 0,
    'negative' => -1,
    'one below the floor' => Protocol::MIN_ARTIFACT_BYTES - 1,
]);

it('accepts an artifact exactly at the floor', function (): void {
    $declaration = fixture('backup.v3/valid.json');
    $declaration['artifact_bytes'] = Protocol::MIN_ARTIFACT_BYTES;

    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->toBe([]);
});

it('refuses a size that is not a whole number of bytes', function (mixed $value): void {
    $declaration = fixture('backup.v3/valid.json');
    $declaration['artifact_bytes'] = $value;

    // Worth pinning now that there is no maximum to fail first. A float here would be a client that
    // has done arithmetic on a size, and a size is the one thing this document is about.
    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->not->toBe([]);
})->with([
    'float' => 2147483648.5,
    'string' => '21474836480',
    'boolean' => true,
    'null' => null,
]);

it('carries no key the platform could use', function (): void {
    $keys = array_keys(fixture('backup.v3/valid.json'));

    expect($keys)->not->toContain('sealed_key')
        ->and($keys)->not->toContain('wrapped_key')
        ->and($keys)->not->toContain('platform_key');

    $schema = json_decode(
        (string) file_get_contents(SchemaValidator::schemaDirectory() . '/backup.v3.json'),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    expect($schema['additionalProperties'])->toBeFalse()
        ->and(array_keys($schema['properties']))->not->toContain('sealed_key');
});

it('names no destination, and would refuse one', function (): void {
    $schema = json_decode(
        (string) file_get_contents(SchemaValidator::schemaDirectory() . '/backup.v3.json'),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    // The multipart upload this version exists to enable is the first time an artifact travels as
    // more than one request. That is exactly the change during which a host, a bucket or a part URL
    // would find its way into the declaration "for convenience". None of them are here, and the
    // connector's own build check refuses a destination read from anything the platform sends.
    foreach (['host', 'bucket', 'endpoint', 'url', 'destination', 'region', 'upload_id', 'parts'] as $forbidden) {
        expect(array_keys($schema['properties']))->not->toContain($forbidden);
    }
});

it('rejects a field the schema does not name', function (): void {
    $errors = SchemaValidator::forSchema('backup.v3')->validate(fixture('backup.v3/unknown-field.json'));

    expect(implode(' ', $errors))->toContain('storage_endpoint');
});

it('rejects credentials, connection details, paths and content samples', function (): void {
    $errors = implode(' ', SchemaValidator::forSchema('backup.v3')->validate(fixture('backup.v3/forbidden-content.json')));

    expect($errors)->toContain('database_password')
        ->and($errors)->toContain('dsn')
        ->and($errors)->toContain('local_path')
        ->and($errors)->toContain('tables')
        ->and($errors)->toContain('sample_rows')
        ->and($errors)->toContain('admin_email');
});

it('never echoes a rejected value back', function (): void {
    $errors = implode(' ', SchemaValidator::forSchema('backup.v3')->validate(fixture('backup.v3/forbidden-content.json')));

    expect($errors)->not->toContain('hunter2')
        ->and($errors)->not->toContain('10.0.0.4')
        ->and($errors)->not->toContain('someone@example.invalid');
});

it('requires everything a platform needs to verify an upload it cannot read', function (string $field): void {
    $declaration = fixture('backup.v3/valid.json');
    unset($declaration[$field]);

    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->not->toBe([]);
})->with([
    'schema_version',
    'job_id',
    'manifest_b64',
    'manifest_sha256',
    'manifest_signature',
    'artifact_sha256',
    'artifact_crc32c',
    'artifact_bytes',
]);

it('pins the schema version rather than accepting any version string', function (string $value): void {
    $declaration = fixture('backup.v3/valid.json');
    $declaration['schema_version'] = $value;

    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->not->toBe([]);
})->with(['backup.v2', 'backup.v4', 'backup', '']);

it('requires a crc alongside the sha, not instead of it', function (): void {
    $schema = json_decode(
        (string) file_get_contents(SchemaValidator::schemaDirectory() . '/backup.v3.json'),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    /*
     | The pair is the point, and it is worth stating as an assertion because the temptation later
     | will be to drop one of them.
     |
     | SHA-256 is the artifact's integrity checksum: signed, covered by the request signature, and
     | what `manager-restore verify` checks offline. CRC-32C is a transport checksum and nothing more
     | - it exists because an object store can confirm a whole-object CRC across a multipart assembly
     | and cannot do the same for a SHA, which does not linearise. Dropping the SHA would trade a
     | cryptographic binding for a forgeable one; dropping the CRC would put the ceiling back.
     */
    expect($schema['required'])->toContain('artifact_sha256')
        ->and($schema['required'])->toContain('artifact_crc32c');
});

it('rejects a crc that is not a crc-32c', function (string $value): void {
    $declaration = fixture('backup.v3/valid.json');
    $declaration['artifact_crc32c'] = $value;

    expect(SchemaValidator::forSchema('backup.v3')->validate($declaration))->not->toBe([]);
})->with([
    'empty' => '',
    'too short' => '7842fa6',
    'too long' => '7842fa6c0',
    'uppercase' => '7842FA6C',
    'not hex' => 'zzzzzzzz',
    'a sha-256 by mistake' => '6d75fe143a2bd66d7190aae125c14f210200cd9eef91289483b8806ea62c01b9',
    'trailing newline' => "7842fa6c\n",
]);

it('agrees with what this runtime computes', function (): void {
    // The fixture's two checksums are derived from a printable fixed seed, the same convention every
    // key in envelope.v2/reference.json follows. Recomputing them here is what makes the fixture a
    // cross-implementation contract rather than two numbers somebody typed.
    $standIn = str_repeat('manager-artifact-v3-fixture-stand-in', 1024);
    $declaration = fixture('backup.v3/valid.json');

    expect($declaration['artifact_sha256'])->toBe(hash('sha256', $standIn))
        ->and($declaration['artifact_crc32c'])->toBe(hash('crc32c', $standIn));
});

it('computes the same crc in one pass as in many', function (): void {
    /*
     | Load-bearing for a twenty-gigabyte artifact, which is never held in memory.
     |
     | The connector computes this checksum incrementally while writing the file. If the streaming
     | form disagreed with the one-shot form the platform would hand the object store a value the
     | assembled object could never match, and the failure would land at the end of a multi-hour
     | upload. crc32c has been in hash_algos() since PHP 7.4, below every floor this protocol
     | supports.
     */
    expect(hash_algos())->toContain('crc32c');

    $bytes = str_repeat('manager-artifact-v3-fixture-stand-in', 1024);

    $context = hash_init('crc32c');

    foreach (str_split($bytes, 997) as $chunk) {
        hash_update($context, $chunk);
    }

    expect(hash_final($context))->toBe(hash('crc32c', $bytes));
});

/*
|-------------------------------------------------------------------------------------------------
| The manifest
|-------------------------------------------------------------------------------------------------
*/

it('accepts the reference v3 manifest', function (): void {
    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate(fixture('backup-manifest.v3/valid.json')))
        ->toBe([]);
});

it('accepts a dump far larger than v2 permitted', function (): void {
    $manifest = fixture('backup-manifest.v3/valid.json');

    // The second half of the same wall. A declaration let through on size would still have been
    // refused here, because `declareV2` validates the decoded manifest too - so both maxima had to go
    // or neither was worth removing.
    expect($manifest['integrity']['plaintext_bytes'])->toBeGreaterThan(Protocol::MAX_ARTIFACT_BYTES)
        ->and($manifest['integrity']['ciphertext_bytes'])->toBeGreaterThan(Protocol::MAX_ARTIFACT_BYTES)
        ->and(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->toBe([]);
});

it('leaves the v2 manifest refusing what it always refused', function (string $field): void {
    $manifest = fixture('backup-manifest.v2/valid.json');
    $manifest['integrity'][$field] = Protocol::MAX_ARTIFACT_BYTES + 1;

    expect(SchemaValidator::forSchema('backup-manifest.v2')->validate($manifest))->not->toBe([]);
})->with(['plaintext_bytes', 'ciphertext_bytes']);

it('still refuses an empty dump', function (string $field): void {
    $manifest = fixture('backup-manifest.v3/valid.json');
    $manifest['integrity'][$field] = 0;

    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);
})->with(['plaintext_bytes', 'ciphertext_bytes']);

it('reads a v3 manifest signature with the v2 rule', function (): void {
    /*
     | The envelope did not move, and this is where that claim is either true or decorative.
     |
     | MANIFEST_SIGNING_PREFIX still says v2 and FORMAT_MAJOR is still 2, deliberately: a v3 artifact
     | differs from a v2 one only in which numbers its manifest is allowed to carry. Had either
     | changed, every artifact ever written would have needed a new reader, and `manager-restore`
     | would have had to grow a second verification path rather than a second schema name.
     |
     | The signature in the fixture is produced by the committed fixture site key, so this verifies a
     | real Ed25519 signature over the exact committed manifest bytes rather than a shape.
     */
    $manifestBytes = fixtureBytes('backup-manifest.v3/valid.json');
    $declaration = fixture('backup.v3/valid.json');
    $reference = fixture('envelope.v2/reference.json');

    expect(base64_decode($declaration['manifest_b64'], true))->toBe($manifestBytes)
        ->and($declaration['manifest_sha256'])->toBe(hash('sha256', $manifestBytes))
        ->and(ArtifactEnvelope::MANIFEST_SIGNING_PREFIX)->toBe("MGRBAK-MANIFEST-v2\n")
        ->and(ArtifactEnvelope::verifyManifest(
            $manifestBytes,
            $declaration['manifest_signature'],
            $reference['keys']['site']['public'],
        ))->toBeTrue();
});

it('rejects a manifest field the schema does not name', function (): void {
    $errors = SchemaValidator::forSchema('backup-manifest.v3')
        ->validate(fixture('backup-manifest.v3/unknown-field.json'));

    expect(implode(' ', $errors))->toContain('database_host');
});

it('rejects a v3 manifest carrying secret key material or a description of the data', function (): void {
    $errors = implode(
        ' ',
        SchemaValidator::forSchema('backup-manifest.v3')->validate(fixture('backup-manifest.v3/forbidden-content.json')),
    );

    expect($errors)->toContain('secret_key')
        ->and($errors)->toContain('private_key')
        ->and($errors)->toContain('dsn')
        ->and($errors)->toContain('database_password')
        ->and($errors)->toContain('local_path')
        ->and($errors)->toContain('tables')
        ->and($errors)->toContain('sample_rows')
        ->and($errors)->not->toContain('hunter2');
});

it('requires everything needed to decrypt a v3 artifact offline', function (string $field): void {
    $manifest = fixture('backup-manifest.v3/valid.json');
    unset($manifest[$field]);

    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);
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

it('pins the v3 manifest version', function (string $value): void {
    $manifest = fixture('backup-manifest.v3/valid.json');
    $manifest['manifest_version'] = $value;

    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);
})->with(['backup-manifest.v2', 'backup-manifest.v4', '']);

it('still pins the chunk size to the one this protocol frames', function (int $chunk): void {
    $manifest = fixture('backup-manifest.v3/valid.json');
    $manifest['encryption']['chunk_bytes'] = $chunk;

    // A larger artifact means more chunks, not larger ones. Nothing about how a reader frames the
    // stream moved, and a v3 that quietly loosened this would produce files v2 readers could not open.
    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);
})->with([
    'smaller' => 4096,
    'larger' => 2097152,
    'off by one' => Protocol::ARTIFACT_CHUNK_BYTES + 1,
]);

it('still bounds how many recipients one artifact may be sealed to', function (): void {
    $manifest = fixture('backup-manifest.v3/valid.json');
    $one = $manifest['key_wrapping']['recipients'][0];

    $manifest['key_wrapping']['recipients'] = array_fill(0, Protocol::MAX_BACKUP_RECIPIENTS, $one);
    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->toBe([]);

    $manifest['key_wrapping']['recipients'] = array_fill(0, Protocol::MAX_BACKUP_RECIPIENTS + 1, $one);
    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);
});

it('accepts only the encryption scheme and key wrapping this protocol implements', function (): void {
    $manifest = fixture('backup-manifest.v3/valid.json');
    $manifest['encryption']['scheme'] = 'aes-256-gcm-v1';

    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);

    $manifest = fixture('backup-manifest.v3/valid.json');
    $manifest['key_wrapping']['algorithm'] = 'rsa-oaep-v1';

    expect(SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest))->not->toBe([]);
});

/*
|-------------------------------------------------------------------------------------------------
| The constants that stopped being a limit
|-------------------------------------------------------------------------------------------------
*/

it('describes a part size a store will accept', function (): void {
    /*
     | S3 requires every part except the last to be at least 5 MiB, and permits at most 10,000 parts.
     | Those two together are what decide whether a given artifact can be uploaded at all, so the
     | default part size has to leave room for the largest artifact anybody would plausibly configure.
     */
    expect(Protocol::ARTIFACT_PART_BYTES)->toBeGreaterThanOrEqual(5 * 1024 * 1024);

    $largest = Protocol::ARTIFACT_PART_BYTES * 10000;

    expect($largest)->toBeGreaterThan(Protocol::MAX_ARTIFACT_BYTES * 1000);
});

it('keeps the single-request threshold where the object store put it', function (): void {
    // 5 GiB, which is S3's documented maximum for one PUT. Above it an upload has to be assembled
    // from parts, which is the whole reason artifact_crc32c exists.
    expect(Protocol::SINGLE_PUT_MAX_BYTES)->toBe(5 * 1024 * 1024 * 1024);
});

it('keeps the default ceiling where it was, now as a default', function (): void {
    /*
     | Unchanged at 2 GiB, and that is deliberate rather than an oversight.
     |
     | The schema no longer refuses a large artifact, so this constant is the only thing standing
     | between a self-hosted operator and a dump that fills the volume their database is on. What
     | changed is who can move it: a platform reads this when its operator has configured nothing, and
     | the hosted edition configures something.
     */
    expect(Protocol::MAX_ARTIFACT_BYTES)->toBe(2 * 1024 * 1024 * 1024)
        ->and(Protocol::MIN_ARTIFACT_BYTES)->toBeLessThan(Protocol::MAX_ARTIFACT_BYTES);
});
