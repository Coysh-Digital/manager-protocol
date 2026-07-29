<?php

declare(strict_types=1);

use coyshdigital\managerprotocol\Jobs;

/**
 * Job types are a closed set. These tests are the gate on widening it.
 */
it('offers no job type that could execute something arbitrary', function (): void {
    // Invariant 8, at the vocabulary level. A job is a named operation with a fixed parameter
    // schema, never a channel for sending instructions.
    foreach (Jobs::reserved() as $type) {
        foreach (['exec', 'eval', 'shell', 'console', 'command', 'sql', 'query', 'http', 'request', 'file', 'read', 'write'] as $forbidden) {
            expect($type)->not->toContain($forbidden);
        }
    }
});

it('keeps the available set to what is actually implemented', function (): void {
    // backup.create is reserved so both sides agree on the spelling, but not available: the
    // specification holds the backup pipeline until its threat model and recovery flow are designed.
    expect(Jobs::available())->toBe(['inventory.refresh', 'updates.check'])
        ->and(Jobs::reserved())->toContain('backup.create')
        ->and(Jobs::isAvailable('backup.create'))->toBeFalse();
});

it('rejects anything not in the set', function (string $type): void {
    expect(Jobs::isAvailable($type))->toBeFalse();
})->with([
    'console runner' => ['console.run'],
    'php eval' => ['php.eval'],
    'sql' => ['sql.query'],
    'shell' => ['shell.exec'],
    'empty' => [''],
    'near miss' => ['inventory.refresh '],
    'case variant' => ['Inventory.Refresh'],
]);

it('bounds a claim batch', function (): void {
    // A site returning from a long outage works through a backlog in batches, rather than being
    // handed hundreds of jobs it cannot finish before they expire.
    expect(Jobs::MAX_CLAIM_BATCH)->toBeGreaterThan(0)->toBeLessThanOrEqual(10);
});

it('names every terminal state', function (): void {
    expect(Jobs::terminalStates())->toContain(Jobs::STATE_SUCCEEDED)
        ->and(Jobs::terminalStates())->toContain(Jobs::STATE_EXPIRED)
        ->and(Jobs::terminalStates())->not->toContain(Jobs::STATE_QUEUED)
        ->and(Jobs::terminalStates())->not->toContain(Jobs::STATE_CLAIMED);
});
