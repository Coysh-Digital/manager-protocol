<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The validator's own behaviour, rather than any one schema's rules.
 *
 * Every other schema test asks whether a particular document is accepted. This one asks whether the
 * validator is capable of refusing at all - which is a different question, and the one that went
 * unasked while `{}` validated against every published schema no matter how many fields it declared
 * required.
 *
 * How that survived is worth keeping in front of whoever changes this next. The suite emptied objects
 * by unsetting one key at a time, so every test payload had at least one key left in it and the empty
 * case was never constructed. `json_decode('{}', true)` returns `[]`, `array_is_list([])` is true, and
 * an empty object was therefore dispatched as an empty *array* - to a branch that returns immediately
 * when the schema declares no `items`, and that has never heard of `required`.
 */

/**
 * Every published schema that declares required fields, and one field each that must be missing from
 * `{}`. Named individually rather than globbed so that adding a schema without adding it here is a
 * visible omission rather than a silent gap in the sweep.
 *
 * @return array<string, array{0: string, 1: string}>
 */
dataset('schemas with required fields', [
    'inventory.v1' => ['inventory.v1', 'collected_at'],
    'system.v1' => ['system.v1', 'collected_at'],
    'system.v2' => ['system.v2', 'collected_at'],
    'updates.v1' => ['updates.v1', 'checked_at'],
    'updates.v2' => ['updates.v2', 'checked_at'],
    'logins.v1' => ['logins.v1', 'failed_attempts'],
    'backup.v1' => ['backup.v1', 'artifact'],
    'backup.v2' => ['backup.v2', 'manifest_signature'],
    'backup.v3' => ['backup.v3', 'artifact_crc32c'],
    'backup-manifest.v2' => ['backup-manifest.v2', 'key_wrapping'],
    'backup-manifest.v3' => ['backup-manifest.v3', 'key_wrapping'],
    'backup-progress.v1' => ['backup-progress.v1', 'stage'],
]);

it('refuses an empty object against a schema with required fields', function (string $schema, string $field): void {
    $errors = SchemaValidator::forSchema($schema)->validate([]);

    expect($errors)->not->toBe([])
        ->and(implode(' ', $errors))->toContain($field);
})->with('schemas with required fields');

it('refuses an empty object nested inside a valid document', function (): void {
    // The shape that matters most: a manifest whose `encryption` block has been emptied. It passed
    // the signature check - the site signed it - and then died on an undefined key downstream rather
    // than being refused here by name.
    $manifest = fixture('backup-manifest.v3/valid.json');
    $manifest['encryption'] = [];

    $errors = SchemaValidator::forSchema('backup-manifest.v3')->validate($manifest);

    expect($errors)->not->toBe([])
        ->and(implode(' ', $errors))->toContain('encryption.');
});

it('still refuses an unknown key on an object that is otherwise empty', function (): void {
    // additionalProperties lives in the same branch as required, so it was skipped by the same bug
    // whenever the object arrived carrying nothing the schema recognised.
    $errors = SchemaValidator::forSchema('inventory.v1')->validate(['not_a_real_field' => 'x']);

    expect(implode(' ', $errors))->toContain('not a permitted field');
});

it('still treats an empty list as a list where the schema says array', function (): void {
    // The other half of the dispatch, and the reason this is keyed on the declared type rather than
    // on emptiness: an empty array is a legitimate value for a list-typed field, and must not start
    // being read as an object with every required field missing.
    $report = fixture('inventory.v1/valid.json');
    $report['plugins'] = [];

    expect(SchemaValidator::forSchema('inventory.v1')->validate($report))->toBe([]);
});

it('accepts every valid fixture unchanged', function (): void {
    // The regression guard for the fix itself. Changing which branch an array takes could only be
    // safe if nothing that validated before stopped validating, and this asserts that directly
    // rather than leaving it to the rest of the suite to notice.
    expect(SchemaValidator::forSchema('inventory.v1')->validate(fixture('inventory.v1/valid.json')))->toBe([])
        ->and(SchemaValidator::forSchema('system.v2')->validate(fixture('system.v2/valid.json')))->toBe([])
        ->and(SchemaValidator::forSchema('updates.v2')->validate(fixture('updates.v2/valid.json')))->toBe([])
        ->and(SchemaValidator::forSchema('logins.v1')->validate(fixture('logins.v1/valid.json')))->toBe([])
        ->and(SchemaValidator::forSchema('backup-manifest.v3')->validate(fixture('backup-manifest.v3/valid.json')))->toBe([]);
});
