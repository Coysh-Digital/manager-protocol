<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The updates schema is the second data-minimisation boundary.
 *
 * v1 refused release notes outright, and the reasoning was sound as far as it went: an advisory body
 * pasted into a dashboard, next to the name of the site it applies to, is a description of an
 * unpatched vulnerability on a named host.
 *
 * v2 accepts them, and the reasoning has not been abandoned so much as located properly. The danger
 * was never the text - it is public, the plugin store serves it to anyone - it was the *association*
 * between that text and a named site, and a schema cannot express where a receiver puts what it is
 * given. So v2 carries the notes and the receiver is required to store them against a plugin and a
 * version rather than against a site. The tests that hold that end of the bargain live in the
 * platform, not here.
 *
 * What both versions still refuse is unchanged and is checked below: no download URLs, no licence
 * keys, nothing that is neither a version nor a description of one.
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

it('accepts a v2 report carrying plugin release notes', function (): void {
    expect(SchemaValidator::forSchema('updates.v2')->validate(fixture('updates.v2/valid.json')))
        ->toBe([]);
});

it('still refuses download URLs and licence keys in v2', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('updates.v2')->validate(fixture('updates.v2/forbidden-content.json')));

    // release_notes on the craft object remains unknown: the notes v2 accepts are per plugin and per
    // version, under a field with a shape, not a free-text blob hung off the top level.
    expect($joined)->toContain('release_notes')
        ->and($joined)->toContain('download_url')
        ->and($joined)->toContain('licence_key')
        ->and($joined)->toContain('licence_keys');
});

it('never echoes a rejected value in v2 either', function (): void {
    $errors = implode(' ', SchemaValidator::forSchema('updates.v2')->validate(fixture('updates.v2/forbidden-content.json')));

    expect($errors)->not->toContain('ABCD-1234')
        ->and($errors)->not->toContain('example.org');
});

it('will not take a v1 payload as v2, or the reverse', function (): void {
    // schema_version is an enum of one in both, so a report cannot be quietly reinterpreted as the
    // other version by a receiver that guessed.
    expect(SchemaValidator::forSchema('updates.v2')->validate(fixture('updates.v1/valid.json')))->not->toBe([])
        ->and(SchemaValidator::forSchema('updates.v1')->validate(fixture('updates.v2/valid.json')))->not->toBe([]);
});

it('bounds how much release note text one report can carry', function (): void {
    $payload = fixture('updates.v2/valid.json');

    $payload['plugins'][0]['releases'] = array_fill(0, 11, ['version' => '3.0.14']);

    expect(implode(' ', SchemaValidator::forSchema('updates.v2')->validate($payload)))
        ->toContain('more items than permitted');

    $payload['plugins'][0]['releases'] = [['version' => '3.0.14', 'notes' => str_repeat('a', 4001)]];

    expect(implode(' ', SchemaValidator::forSchema('updates.v2')->validate($payload)))
        ->toContain('exceeds its maximum length');
});

it('requires a version on every release it is given', function (): void {
    $payload = fixture('updates.v2/valid.json');

    // Notes with no version cannot be filtered against what a site is running, so they would be
    // rendered to everyone regardless of whether they apply.
    $payload['plugins'][0]['releases'] = [['notes' => 'Fixed a thing.']];

    expect(SchemaValidator::forSchema('updates.v2')->validate($payload))->not->toBe([]);
});
