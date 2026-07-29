<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\ProtocolException;
use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The inventory schema is the data-minimisation boundary. These tests exist to make it expensive to
 * widen it by accident.
 */
it('accepts a realistic report from a healthy site', function (): void {
    expect(SchemaValidator::forSchema('inventory.v1')->validate(fixture('inventory.v1/valid.json')))
        ->toBe([]);
});

it('rejects a field the schema does not permit', function (): void {
    // Stripping unknown keys instead would let a connector widen what it collects unnoticed.
    $errors = SchemaValidator::forSchema('inventory.v1')->validate(fixture('inventory.v1/unknown-field.json'));

    expect($errors)->toHaveCount(1)
        ->and($errors[0])->toContain('site_admin_email')
        ->and($errors[0])->toContain('not a permitted field');
});

it('rejects site content, user records, credentials and environment values', function (): void {
    $errors = SchemaValidator::forSchema('inventory.v1')->validate(fixture('inventory.v1/forbidden-content.json'));

    $joined = implode(' ', $errors);

    // Every one of these is named in the spec's "must not contain" list.
    expect($joined)->toContain('entries')
        ->and($joined)->toContain('users')
        ->and($joined)->toContain('env')
        ->and($joined)->toContain('password')
        ->and($joined)->toContain('host');
});

it('never echoes a rejected value into the error message', function (): void {
    // Error strings reach logs, and a rejected payload may carry key material.
    $errors = SchemaValidator::forSchema('inventory.v1')->validate(fixture('inventory.v1/forbidden-content.json'));

    $joined = implode(' ', $errors);

    expect($joined)->not->toContain('hunter2')
        ->and($joined)->not->toContain('admin@example.org')
        ->and($joined)->not->toContain('should never be transmitted');
});

it('requires the fields the platform depends on', function (string $missing): void {
    $payload = fixture('inventory.v1/valid.json');
    unset($payload[$missing]);

    $errors = SchemaValidator::forSchema('inventory.v1')->validate($payload);

    expect($errors)->not->toBe([])
        ->and(implode(' ', $errors))->toContain($missing);
})->with(['schema_version', 'collected_at', 'connector', 'craft', 'php', 'database', 'environment']);

it('pins the payload to a schema version', function (): void {
    $payload = fixture('inventory.v1/valid.json');
    $payload['schema_version'] = 'inventory.v2';

    expect(SchemaValidator::forSchema('inventory.v1')->validate($payload))->not->toBe([]);
});

it('enforces enums on classification fields', function (string $field, mixed $value): void {
    $payload = fixture('inventory.v1/valid.json');
    data_set_by_path($payload, $field, $value);

    expect(SchemaValidator::forSchema('inventory.v1')->validate($payload))->not->toBe([]);
})->with([
    'environment' => ['environment', 'somewhere-else'],
    'craft edition' => ['craft.edition', 'enterprise'],
    'database engine' => ['database.engine', 'sqlite'],
    'licence state' => ['licence.craft', 'probably-fine'],
]);

it('rejects a boolean where an integer is required', function (): void {
    // PHP would happily treat true as 1 without an explicit guard.
    $payload = fixture('inventory.v1/valid.json');
    $payload['queue']['pending'] = true;

    expect(SchemaValidator::forSchema('inventory.v1')->validate($payload))->not->toBe([]);
});

it('caps list lengths so one site cannot post an unbounded payload', function (): void {
    $payload = fixture('inventory.v1/valid.json');
    $payload['plugins'] = array_fill(0, 251, ['handle' => 'a', 'version' => '1.0.0', 'enabled' => true]);

    expect(implode(' ', SchemaValidator::forSchema('inventory.v1')->validate($payload)))
        ->toContain('more items than permitted');
});

it('validates nested list items', function (): void {
    $payload = fixture('inventory.v1/valid.json');
    $payload['plugins'][0]['handle'] = 'not a valid handle!';

    expect(implode(' ', SchemaValidator::forSchema('inventory.v1')->validate($payload)))
        ->toContain('does not match the permitted format');
});

it('refuses to load a schema name that is not registered', function (string $name): void {
    expect(fn () => SchemaValidator::forSchema($name))->toThrow(ProtocolException::class);
})->with([
    'traversal' => ['../composer'],
    'unknown' => ['backups.v1'],
    'malformed' => ['not-a-schema'],
]);

it('throws with assertValid but returns a list with validate', function (): void {
    $validator = SchemaValidator::forSchema('inventory.v1');

    expect(fn () => $validator->assertValid(fixture('inventory.v1/unknown-field.json')))
        ->toThrow(ProtocolException::class)
        ->and($validator->validate(fixture('inventory.v1/valid.json')))->toBe([]);

    $validator->assertValid(fixture('inventory.v1/valid.json'));
});

/**
 * Set a dotted path inside a nested array.
 *
 * @param array<string, mixed> $target
 */
function data_set_by_path(array &$target, string $path, mixed $value): void
{
    $keys = explode('.', $path);
    $cursor = &$target;

    foreach ($keys as $key) {
        if (!isset($cursor[$key]) || !is_array($cursor[$key])) {
            $cursor[$key] = [];
        }
        $cursor = &$cursor[$key];
    }

    $cursor = $value;
}
