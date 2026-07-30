<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The runtime schema is where "measure the disk" has to stop short of "read the disk".
 *
 * A byte count says how much is there. A file name says what. The gap between those two is the whole
 * boundary this schema defends, and it is easy to cross by accident — the obvious implementation of
 * "show me my largest volumes" wants to list the largest files in them, and the obvious
 * implementation of "why is this site slow" wants to name the slow URLs. Both would be useful. Both
 * are somebody else's content and somebody else's visitors.
 */
it('accepts a realistic runtime report', function (): void {
    expect(SchemaValidator::forSchema('system.v1')->validate(fixture('system.v1/valid.json')))
        ->toBe([]);
});

it('rejects paths, file names, phpinfo and visitor addresses', function (): void {
    $errors = SchemaValidator::forSchema('system.v1')->validate(fixture('system.v1/forbidden-content.json'));

    $joined = implode(' ', $errors);

    expect($joined)->toContain('path')
        ->and($joined)->toContain('largest_files')
        ->and($joined)->toContain('web_root')
        ->and($joined)->toContain('phpinfo')
        ->and($joined)->toContain('ini_path')
        ->and($joined)->toContain('slowest_urls')
        ->and($joined)->toContain('client_ips');
});

it('never echoes a rejected value', function (): void {
    // A validation message that quoted the offending value would store the thing the allowlist
    // exists to keep out, in the one place an operator is most likely to paste into a ticket.
    $joined = implode(' ', SchemaValidator::forSchema('system.v1')->validate(fixture('system.v1/forbidden-content.json')));

    expect($joined)->not->toContain('board-minutes')
        ->and($joined)->not->toContain('staff-salaries')
        ->and($joined)->not->toContain('/var/www')
        ->and($joined)->not->toContain('203.0.113.9');
});

it('keeps an unmeasured volume distinguishable from an empty one', function (): void {
    // A volume nobody could walk and a volume with nothing in it are different facts, and only one
    // of them should worry anybody. Reporting the first as zero is how somebody concludes an asset
    // volume was emptied overnight.
    // Plain PHP: this package has zero runtime dependencies, so there is no collect() here.
    $volumes = fixture('system.v1/valid.json')['storage']['volumes'];

    $archive = array_values(array_filter(
        $volumes,
        static fn (array $volume): bool => $volume['handle'] === 'archive',
    ))[0];

    expect($archive['measured'])->toBeFalse()
        ->and($archive['bytes'])->toBe(0);
});

it('permits an unlimited memory limit, which is a real setting', function (): void {
    $payload = fixture('system.v1/valid.json');
    $payload['php']['memory_limit_bytes'] = -1;

    expect(SchemaValidator::forSchema('system.v1')->validate($payload))->toBe([]);
});

it('refuses a negative byte count, which is not', function (): void {
    $payload = fixture('system.v1/valid.json');
    $payload['storage']['volumes'][0]['bytes'] = -1;

    expect(SchemaValidator::forSchema('system.v1')->validate($payload))->not->toBe([]);
});

it('refuses a volume handle that could smuggle a path', function (): void {
    $payload = fixture('system.v1/valid.json');
    $payload['storage']['volumes'][0]['handle'] = '../../etc/passwd';

    expect(SchemaValidator::forSchema('system.v1')->validate($payload))->not->toBe([]);
});

it('is valid with nothing but the core fields', function (): void {
    // Every section is optional. A site whose volumes are all remote, with no opcache and too little
    // traffic to sample, sends almost nothing — and that is a valid report rather than a deficient
    // one.
    expect(SchemaValidator::forSchema('system.v1')->validate([
        'schema_version' => 'system.v1',
        'collected_at' => 1785400000,
    ]))->toBe([]);
});
