<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\Protocol;

/**
 * The package states its version twice, and a release states it a third time in the git tag.
 *
 * This test exists because the connector's two drifted: its constant went to 1.2.0 while composer.json
 * stayed at 1.1.0, so Packagist saw a tag disagreeing with the manifest and published nothing. Nothing
 * failed loudly - the package simply had no versions.
 *
 * Invariant 17 asks for verifiable release artifacts. A release carrying two different version numbers
 * is not verifiable, so this is checked rather than remembered.
 */
it('states one version, not two', function (): void {
    $manifest = json_decode(
        (string) file_get_contents(dirname(__DIR__).'/composer.json'),
        true,
        512,
        JSON_THROW_ON_ERROR,
    );

    expect($manifest['version'] ?? null)
        ->not->toBeNull('composer.json has no version field, but Protocol::VERSION does.')
        ->and($manifest['version'])->toBe(Protocol::VERSION);
});

it('uses a version a release can be tagged as', function (): void {
    // Semantic, three-part, no prefix. The tag adds the "v"; the manifest must not.
    expect(Protocol::VERSION)->toMatch('/^\d+\.\d+\.\d+$/');
});
