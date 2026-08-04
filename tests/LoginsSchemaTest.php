<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The sign-in schema is the strictest boundary in the protocol, and the one with the least room for
 * good intentions.
 *
 * Every other schema draws a line somewhere reasonable people might argue about. This one does not:
 * a monitoring platform has no business holding a record of who tried to sign in to somebody else's
 * website, from where, and when. The operator's question is "is this site being attacked, and is
 * anybody locked out". That is four integers.
 *
 * The pressure to add more is real and will recur - a username makes the finding actionable, an
 * address makes it blockable - so the refusal lives in a schema with `additionalProperties: false`
 * rather than in a code review somebody has to remember to do.
 */
it('accepts a realistic sign-in report', function (): void {
    expect(SchemaValidator::forSchema('logins.v1')->validate(fixture('logins.v1/valid.json')))
        ->toBe([]);
});

it('rejects usernames, addresses and per-attempt records', function (): void {
    $errors = SchemaValidator::forSchema('logins.v1')->validate(fixture('logins.v1/forbidden-content.json'));

    $joined = implode(' ', $errors);

    expect($joined)->toContain('usernames')
        ->and($joined)->toContain('emails')
        ->and($joined)->toContain('source_ips')
        ->and($joined)->toContain('attempts');
});

it('never echoes a rejected value', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('logins.v1')->validate(fixture('logins.v1/forbidden-content.json')));

    expect($joined)->not->toContain('j.hartley')
        ->and($joined)->not->toContain('jane.hartley@example.org')
        ->and($joined)->not->toContain('203.0.113.9')
        ->and($joined)->not->toContain('curl/8.4.0');
});

it('requires the count that the whole report is for', function (): void {
    $payload = fixture('logins.v1/valid.json');
    unset($payload['failed_attempts']);

    expect(SchemaValidator::forSchema('logins.v1')->validate($payload))->not->toBe([]);
});

it('bounds the window', function (): void {
    // An unbounded window makes every count monotonic and therefore meaningless: "1,400 failed
    // attempts, ever" tells nobody whether anything is happening now.
    $payload = fixture('logins.v1/valid.json');
    $payload['window_hours'] = 100000;

    expect(SchemaValidator::forSchema('logins.v1')->validate($payload))->not->toBe([]);
});

it('refuses a negative count', function (): void {
    $payload = fixture('logins.v1/valid.json');
    $payload['accounts_locked'] = -1;

    expect(SchemaValidator::forSchema('logins.v1')->validate($payload))->not->toBe([]);
});

it('is valid with no failures to report', function (): void {
    // The common case, and it must be expressible without the optional timestamp.
    expect(SchemaValidator::forSchema('logins.v1')->validate([
        'schema_version' => 'logins.v1',
        'collected_at' => 1785400000,
        'window_hours' => 24,
        'failed_attempts' => 0,
    ]))->toBe([]);
});
