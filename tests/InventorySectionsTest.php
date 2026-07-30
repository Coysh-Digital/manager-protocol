<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\InventorySections;
use coyshdigital\managerprotocol\Protocol;

/**
 * Granting a capability has to change what a site sends, or the interface is describing a permission
 * that does nothing.
 */
it('sends only the core sections with no capabilities at all', function (): void {
    $filtered = InventorySections::filter(fixture('inventory.v1/valid.json'), []);

    expect(array_keys($filtered))->toBe(InventorySections::core())
        ->and($filtered)->not->toHaveKey('licence')
        ->and($filtered)->not->toHaveKey('config_flags')
        ->and($filtered)->not->toHaveKey('queue')
        ->and($filtered)->not->toHaveKey('plugins');
});

it('unlocks exactly one section group per capability', function (string $capability, array $expected): void {
    $filtered = InventorySections::filter(fixture('inventory.v1/valid.json'), [$capability]);

    foreach ($expected as $section) {
        expect($filtered)->toHaveKey($section);
    }

    // And nothing another capability governs.
    foreach (InventorySections::map() as $other => $sections) {
        if ($other === $capability) {
            continue;
        }

        foreach ($sections as $section) {
            expect($filtered)->not->toHaveKey($section);
        }
    }
})->with([
    'inventory' => ['inventory:read', ['plugins', 'composer_packages']],
    'licences' => ['licences:read', ['licence']],
    'security' => ['security:read', ['config_flags']],
    'system' => ['system:read', ['queue', 'migrations']],
]);

it('still validates when sections are withheld', function (): void {
    // A site holding only inventory:read produces a shorter report, not an invalid one.
    $filtered = InventorySections::filter(fixture('inventory.v1/valid.json'), ['inventory:read']);

    expect(coyshdigital\managerprotocol\SchemaValidator::forSchema('inventory.v1')->validate($filtered))
        ->toBe([]);
});

it('never withholds a core section', function (): void {
    foreach (InventorySections::core() as $section) {
        expect(InventorySections::capabilityFor($section))->toBeNull();
    }
});

it('governs every optional section by some capability', function (): void {
    $schema = json_decode(
        (string) file_get_contents(coyshdigital\managerprotocol\SchemaValidator::schemaDirectory().'/inventory.v1.json'),
        true,
    );

    // Anything the schema permits is either core or gated. A section governed by nothing would be
    // sent unconditionally, which is the gap this test exists to catch.
    foreach (array_keys($schema['properties']) as $section) {
        $governed = in_array($section, InventorySections::core(), true)
            || InventorySections::capabilityFor($section) !== null;

        expect($governed)->toBeTrue("'{$section}' is neither core nor gated by a capability");
    }
});

it('maps only capabilities the protocol defines', function (): void {
    foreach (array_keys(InventorySections::map()) as $capability) {
        expect(Protocol::capabilities())->toContain($capability)
            // Every section-gating capability is read-only. A write capability has no business
            // deciding what a report contains.
            ->and(Protocol::isReadOnlyCapability($capability))->toBeTrue();
    }
});
