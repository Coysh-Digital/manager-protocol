<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The updates schema is the second data-minimisation boundary.
 *
 * The platform needs to know *that* an update exists and whether it is a security release. It does
 * not need the release notes, and it certainly does not need a download URL — an advisory body
 * pasted into a dashboard is a description of an unpatched vulnerability on a named site.
 */
it('accepts a realistic update report', function (): void {
    expect(SchemaValidator::forSchema('updates.v1')->validate(fixture('updates.v1/valid.json')))
        ->toBe([]);
});

it('rejects release notes, download URLs and licence keys', function (): void {
    $errors = SchemaValidator::forSchema('updates.v1')->validate(fixture('updates.v1/forbidden-content.json'));

    $joined = implode(' ', $errors);

    expect($joined)->toContain('release_notes')
        ->and($joined)->toContain('download_url')
        ->and($joined)->toContain('licence_keys');
});

it('never echoes a rejected value', function (): void {
    $errors = SchemaValidator::forSchema('updates.v1')->validate(fixture('updates.v1/forbidden-content.json'));

    expect(implode(' ', $errors))->not->toContain('authentication bypass')
        ->and(implode(' ', $errors))->not->toContain('ABCD-1234');
});

it('requires the field that decides urgency', function (): void {
    $payload = fixture('updates.v1/valid.json');

    // security_release_available is optional in the schema, but update_available is not: a report
    // that cannot say whether an update exists is useless.
    unset($payload['craft']['update_available']);

    expect(SchemaValidator::forSchema('updates.v1')->validate($payload))->not->toBe([]);
});

it('caps the plugin list', function (): void {
    $payload = fixture('updates.v1/valid.json');
    $payload['plugins'] = array_fill(0, 251, ['handle' => 'a', 'current' => '1.0.0', 'update_available' => false]);

    expect(implode(' ', SchemaValidator::forSchema('updates.v1')->validate($payload)))
        ->toContain('more items than permitted');
});
