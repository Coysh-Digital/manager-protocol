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

/*
 | system.v4.
 |
 | v1 to v3 are untouched. What v4 adds is a single declared value, and the question worth a test is
 | whether it stays one. A file that says which Node version a project wants is also a file that holds
 | a path, a registry address or a token when somebody puts one there, and the temptation on the
 | connector side is to send whatever was read - so the schema refuses anything that is not shaped
 | like a version, and refuses the more informative answers (what is installed, what the manifest
 | says besides) by name.
 */
it('accepts a v4 report declaring the Node.js version', function (): void {
    expect(SchemaValidator::forSchema('system.v4')->validate(fixture('system.v4/valid.json')))
        ->toBe([]);
});

it('refuses the more informative half of every fact v4 added', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('system.v4')->validate(fixture('system.v4/forbidden-content.json')));

    // A path where the version goes, a path where the file name goes, a path beside them, the
    // version that is actually running, the rest of the engines block and the contents of a
    // registry configuration.
    expect($joined)->toContain('.declared does not match the permitted format')
        ->and($joined)->toContain('.source is not one of the permitted values')
        ->and($joined)->toContain('.path is not a permitted field')
        ->and($joined)->toContain('.running is not a permitted field')
        ->and($joined)->toContain('.engines is not a permitted field')
        ->and($joined)->toContain('.contents is not a permitted field');
});

it('never echoes a rejected v4 value either', function (): void {
    $joined = implode(' ', SchemaValidator::forSchema('system.v4')->validate(fixture('system.v4/forbidden-content.json')));

    expect($joined)->not->toContain('/var/www')
        ->and($joined)->not->toContain('example.org')
        ->and($joined)->not->toContain('_authToken')
        ->and($joined)->not->toContain('private-registry');
});

it('accepts the shapes a Node version or range is written in', function (string $declared): void {
    $payload = fixture('system.v4/valid.json');
    $payload['node']['declared'] = $declared;

    expect(SchemaValidator::forSchema('system.v4')->validate($payload))->toBe([]);
})->with([
    'major' => '20',
    'prefixed' => 'v20.11.0',
    'wildcard' => '20.x',
    'range' => '>=18.17 <21',
    'alternatives' => '^18 || ^20',
    'tilde' => '~20.11.0',
    'prerelease' => '22.0.0-rc.1+build.5',
    'latest lts' => 'lts/*',
    'named lts' => 'lts/iron',
    'alias' => 'node',
]);

it('refuses a declared value that could carry a path, a url or a sentence', function (string $declared): void {
    $payload = fixture('system.v4/valid.json');
    $payload['node']['declared'] = $declared;

    expect(SchemaValidator::forSchema('system.v4')->validate($payload))->not->toBe([]);
})->with([
    'absolute path' => '/var/www/html/.nvmrc',
    'relative path' => '../../etc/passwd',
    'windows path' => 'C:\\sites\\acme',
    'url' => 'https://npm.example.org',
    'lts alias with a path' => 'lts/../../etc',
    'sentence' => 'whatever the client uses, ask Dave',
    'shell' => '20; rm -rf /',
    'interpolation' => '$NODE_VERSION',
    'empty' => '',
    'newline' => "20\n/var/www",
]);

it('caps declared at thirty-two characters', function (): void {
    $payload = fixture('system.v4/valid.json');

    $payload['node']['declared'] = str_repeat('2', 32);
    expect(SchemaValidator::forSchema('system.v4')->validate($payload))->toBe([]);

    $payload['node']['declared'] = str_repeat('2', 33);
    expect(implode(' ', SchemaValidator::forSchema('system.v4')->validate($payload)))
        ->toContain('node.declared exceeds its maximum length');
});

it('refuses a declared value that is not a string', function (): void {
    // The type is ["string", "null"], and a list of types that matched anything would be worse than
    // having no type at all.
    foreach ([20, 20.5, true, ['20'], ['node' => '20']] as $declared) {
        $payload = fixture('system.v4/valid.json');
        $payload['node']['declared'] = $declared;

        expect(SchemaValidator::forSchema('system.v4')->validate($payload))->not->toBe([]);
    }
});

it('keeps source to the three files a version is read from', function (): void {
    foreach (['.nvmrc', '.node-version', 'package.json'] as $source) {
        $payload = fixture('system.v4/valid.json');
        $payload['node']['source'] = $source;

        expect(SchemaValidator::forSchema('system.v4')->validate($payload))->toBe([]);
    }

    // The tempting extras: a path to the file, the lockfile beside it, the registry configuration
    // that can hold a token.
    foreach (['/var/www/html/.nvmrc', 'package-lock.json', '.npmrc', 'nvmrc', ''] as $source) {
        $payload = fixture('system.v4/valid.json');
        $payload['node']['source'] = $source;

        expect(SchemaValidator::forSchema('system.v4')->validate($payload))->not->toBe([]);
    }
});

it('refuses an unknown key inside node', function (): void {
    $payload = fixture('system.v4/valid.json');
    $payload['node']['npm'] = '>=9';

    expect(implode(' ', SchemaValidator::forSchema('system.v4')->validate($payload)))
        ->toContain('node.npm is not a permitted field');
});

it('tells a site that declares nothing apart from a connector that did not look', function (): void {
    // Both members null is an answer: the connector read the project, and nothing there names a
    // version. No `node` at all is the absence of an answer - an older connector, or one that could
    // not read the project - and v4 refuses it, so the platform never has to guess which it is
    // looking at.
    $declaresNothing = fixture('system.v4/valid.json');
    $declaresNothing['node'] = ['declared' => null, 'source' => null];

    expect(SchemaValidator::forSchema('system.v4')->validate($declaresNothing))->toBe([]);

    $neverLooked = fixture('system.v4/valid.json');
    unset($neverLooked['node']);

    expect(implode(' ', SchemaValidator::forSchema('system.v4')->validate($neverLooked)))
        ->toContain('$.node is required');
});

it('requires both members of node to be present, even when null', function (): void {
    foreach (['declared', 'source'] as $member) {
        $payload = fixture('system.v4/valid.json');
        unset($payload['node'][$member]);

        expect(implode(' ', SchemaValidator::forSchema('system.v4')->validate($payload)))
            ->toContain("\$.node.{$member} is required");
    }
});

it('refuses node as anything but an object', function (): void {
    foreach ([null, '20', ['20'], 20] as $node) {
        $payload = fixture('system.v4/valid.json');
        $payload['node'] = $node;

        expect(SchemaValidator::forSchema('system.v4')->validate($payload))->not->toBe([]);
    }
});

it('is valid with node and the core fields, as v1 to v3 are with the core alone', function (): void {
    expect(SchemaValidator::forSchema('system.v4')->validate([
        'schema_version' => 'system.v4',
        'collected_at' => 1785400000,
        'node' => ['declared' => null, 'source' => null],
    ]))->toBe([]);
});

it('will not accept a v3 report under the v4 name, or the reverse', function (): void {
    $v3 = fixture('system.v3/valid.json');

    expect(SchemaValidator::forSchema('system.v4')->validate($v3))->not->toBe([]);

    $v4 = fixture('system.v4/valid.json');

    expect(SchemaValidator::forSchema('system.v3')->validate($v4))->not->toBe([]);
});

it('leaves system.v3 exactly as it was', function (): void {
    // Add-only means a v3 connector is still a valid v3 connector. The tempting way to break that
    // is to make `node` optional on v3 "for consistency"; this is the test that says no.
    $v3 = fixture('system.v3/valid.json');
    $v3['node'] = ['declared' => '20', 'source' => '.nvmrc'];

    expect(SchemaValidator::forSchema('system.v3')->validate($v3))->not->toBe([])
        ->and(SchemaValidator::forSchema('system.v3')->validate(fixture('system.v3/valid.json')))->toBe([]);
});
