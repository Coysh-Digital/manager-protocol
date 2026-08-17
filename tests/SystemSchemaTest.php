<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\SchemaValidator;

/**
 * The runtime schema is where "measure the disk" has to stop short of "read the disk".
 *
 * A byte count says how much is there. A file name says what. The gap between those two is the whole
 * boundary this schema defends, and it is easy to cross by accident - the obvious implementation of
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
    // traffic to sample, sends almost nothing - and that is a valid report rather than a deficient
    // one.
    expect(SchemaValidator::forSchema('system.v1')->validate([
        'schema_version' => 'system.v1',
        'collected_at' => 1785400000,
    ]))->toBe([]);
});

/*
 | system.v2.
 |
 | v1 is untouched and still refuses everything it refused, so a v1 connector and a v2 platform stay
 | compatible in both directions.
 |
 | What v2 adds is two categories per volume, and the interesting question is not whether they
 | validate but whether they stay categories. `location` exists so a screen can say the bytes are not
 | on the server's disk; the moment it can carry a bucket, a region, an endpoint or an adapter class
 | it is naming a customer's infrastructure instead, which is the same boundary `path` and
 | `largest_files` are on the wrong side of.
 */
it('accepts a v2 report that says where each volume lives and why it went unmeasured', function (): void {
    expect(SchemaValidator::forSchema('system.v2')->validate(fixture('system.v2/valid.json')))
        ->toBe([]);
});

it('refuses to let location become the name of somebody\'s infrastructure', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('system.v2')->validate(fixture('system.v2/forbidden-content.json')));

    expect($joined)->toContain('bucket')
        ->and($joined)->toContain('region')
        ->and($joined)->toContain('endpoint')
        ->and($joined)->toContain('adapter')
        ->and($joined)->toContain('path')
        ->and($joined)->toContain('largest_files');
});

it('never echoes a rejected v2 value either', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('system.v2')->validate(fixture('system.v2/forbidden-content.json')));

    expect($joined)->not->toContain('acme-production-uploads')
        ->and($joined)->not->toContain('eu-west-2')
        ->and($joined)->not->toContain('board-minutes')
        ->and($joined)->not->toContain('/var/www');
});

it('keeps location to the two values a screen can act on', function (): void {
    // "s3" is the tempting third value and the one that starts the slide: a provider name invites a
    // bucket beside it. What a reader needs to know is whether the bytes count towards the disk,
    // and that has two answers.
    $payload = fixture('system.v2/valid.json');
    $payload['storage']['volumes'][0]['location'] = 's3';

    expect(SchemaValidator::forSchema('system.v2')->validate($payload))->not->toBe([]);
});

it('distinguishes the three reasons a volume goes unmeasured', function (): void {
    /*
     * The whole point of the version. v1 said `measured: false` for remote storage, for a walk that
     * ran out of its time budget, and for a path that could not be opened - three situations
     * wanting three different responses: nothing, a larger budget, and someone fixing a
     * misconfiguration.
     */
    $volumes = fixture('system.v2/valid.json')['storage']['volumes'];

    $reasons = [];

    foreach ($volumes as $volume) {
        if (($volume['measured'] ?? true) === false) {
            $reasons[$volume['handle']] = $volume['unmeasured_reason'];
        }
    }

    expect($reasons)->toBe([
        'archive' => 'remote',
        'video' => 'timeout',
        'legacy' => 'unreadable',
    ]);

    // And a made-up fourth reason is not a reason.
    $payload = fixture('system.v2/valid.json');
    $payload['storage']['volumes'][2]['unmeasured_reason'] = 'because';

    expect(SchemaValidator::forSchema('system.v2')->validate($payload))->not->toBe([]);
});

it('lets a timed-out walk report the bytes it did reach', function (): void {
    // A floor, not a total, and the platform is told which. Refusing partial figures would throw
    // away the only number a huge volume ever produces.
    $volumes = fixture('system.v2/valid.json')['storage']['volumes'];

    $video = array_values(array_filter(
        $volumes,
        static fn (array $volume): bool => $volume['handle'] === 'video',
    ))[0];

    expect($video['measured'])->toBeFalse()
        ->and($video['unmeasured_reason'])->toBe('timeout')
        ->and($video['bytes'])->toBeGreaterThan(0);
});

it('still accepts a v2 report from a site that can say neither', function (): void {
    // Both fields are optional. A connector that cannot tell - an adapter shape it does not
    // recognise - omits them rather than guessing, and the platform shows what v1 showed.
    expect(SchemaValidator::forSchema('system.v2')->validate([
        'schema_version' => 'system.v2',
        'collected_at' => 1785400000,
        'storage' => ['volumes' => [['handle' => 'images', 'bytes' => 1024, 'measured' => true]]],
    ]))->toBe([]);
});

it('will not accept a v1 report under the v2 name, or the reverse', function (): void {
    // The version string is part of the contract rather than a label on it.
    $v1 = fixture('system.v1/valid.json');

    expect(SchemaValidator::forSchema('system.v2')->validate($v1))->not->toBe([]);

    $v2 = fixture('system.v2/valid.json');

    expect(SchemaValidator::forSchema('system.v1')->validate($v2))->not->toBe([]);
});

/*
 | system.v3.
 |
 | v1 and v2 are untouched, so every combination of connector and platform that worked before still
 | works and nothing has to be upgraded in step.
 |
 | What v3 adds is the first set of facts in this schema that a site could answer *usefully* by
 | sending something identifying. A deprecation warning is only actionable if you know which template
 | raised it; a database size is only actionable if you know which table grew; a moved control panel
 | is only findable if you know where it moved to. In every one of those cases the useful answer is
 | the site's code, the shape of its content, or a secret it moved on purpose - so v3 sends the
 | count, the total and the boolean, and these tests are the reason it keeps doing so.
 */
it('accepts a v3 report describing the Craft install', function (): void {
    expect(SchemaValidator::forSchema('system.v3')->validate(fixture('system.v3/valid.json')))
        ->toBe([]);
});

it('refuses the identifying half of every fact v3 added', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('system.v3')->validate(fixture('system.v3/forbidden-content.json')));

    // The security key beside the boolean that says one is set, the trigger beside the boolean that
    // says it moved, the deprecation messages beside their count, the table list beside the total
    // size, a path beside the writability it describes, and the loaded-extension list beside the
    // count that exists precisely so the list does not have to travel.
    expect($joined)->toContain('.security_key is')
        ->and($joined)->toContain('.cp_trigger is')
        ->and($joined)->toContain('.messages is')
        ->and($joined)->toContain('.tables is')
        ->and($joined)->toContain('.name is')
        ->and($joined)->toContain('.path is')
        ->and($joined)->toContain('.web_root is')
        ->and($joined)->toContain('.loaded is')
        ->and($joined)->toContain('.ini_path is');
});

it('never echoes a rejected v3 value either', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('system.v3')->validate(fixture('system.v3/forbidden-content.json')));

    expect($joined)->not->toContain('vFq3mZ8pR2wK7nT4xL9dB6sG1hJ5cY0a')
        ->and($joined)->not->toContain('acme-secret-panel')
        ->and($joined)->not->toContain('acme_production')
        ->and($joined)->not->toContain('Payroll.php')
        ->and($joined)->not->toContain('/var/www');
});

it('keeps missing_extensions to Craft\'s published requirements', function (): void {
    /*
     * The field that would most easily become the thing `extensions` refuses to be. Free strings
     * here and a connector could report every loaded extension by calling them all "missing" — so
     * the values are an enum, and anything outside it is refused rather than trimmed.
     */
    $payload = fixture('system.v3/valid.json');
    $payload['php']['missing_extensions'] = ['ioncube_loader'];

    expect(SchemaValidator::forSchema('system.v3')->validate($payload))->not->toBe([]);
});

it('keeps the image driver to which library, not which version', function (): void {
    // A version string belongs to the host. What a reader acts on is whether transforms can happen
    // at all, and that has three answers.
    $payload = fixture('system.v3/valid.json');
    $payload['php']['image_driver'] = 'imagick 3.7.0';

    expect(SchemaValidator::forSchema('system.v3')->validate($payload))->not->toBe([]);
});

it('keeps writable directories to the ones Craft owns', function (): void {
    // A free-form label here is a filesystem path with extra steps: "/var/www/html/storage": true
    // reports a path while looking like it reports a permission.
    $payload = fixture('system.v3/valid.json');
    $payload['paths']['/var/www/vhosts/example.org/storage'] = true;

    expect(SchemaValidator::forSchema('system.v3')->validate($payload))->not->toBe([]);
});

it('tells an empty missing_extensions apart from an absent one', function (): void {
    // A site that checked and found nothing missing, and a connector too old to have looked, are
    // different facts. Both are valid; only one of them means the extensions are fine.
    $checked = fixture('system.v3/valid.json');
    $checked['php']['missing_extensions'] = [];

    expect(SchemaValidator::forSchema('system.v3')->validate($checked))->toBe([]);

    $neverLooked = fixture('system.v3/valid.json');
    unset($neverLooked['php']['missing_extensions']);

    expect(SchemaValidator::forSchema('system.v3')->validate($neverLooked))->toBe([]);
});

it('is valid with nothing but the core fields, as v1 and v2 are', function (): void {
    // Every section stays optional. A connector that can build a v3 report but whose Craft could not
    // answer any of the new questions sends a shorter report, not a deficient one.
    expect(SchemaValidator::forSchema('system.v3')->validate([
        'schema_version' => 'system.v3',
        'collected_at' => 1785400000,
    ]))->toBe([]);
});

it('will not accept a v2 report under the v3 name, or the reverse', function (): void {
    $v2 = fixture('system.v2/valid.json');

    expect(SchemaValidator::forSchema('system.v3')->validate($v2))->not->toBe([]);

    $v3 = fixture('system.v3/valid.json');

    expect(SchemaValidator::forSchema('system.v2')->validate($v3))->not->toBe([]);
});
