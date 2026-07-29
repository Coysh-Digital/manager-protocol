<?php

/**
 * Manager protocol.
 *
 * @link      https://coysh.digital
 * @copyright Copyright (c) Coysh Digital
 */

declare(strict_types=1);

namespace coyshdigital\managerprotocol;

/**
 * The remote job vocabulary both sides share.
 *
 * Job types are a **closed set**, declared here so that neither side can invent one. The platform
 * refuses to enqueue a type it does not know; the connector refuses to execute one. Both refusals
 * matter — the platform's stops a mistake, the connector's stops a compromised platform.
 *
 * What is deliberately absent is the whole point. There is no `console.run`, no `php.eval`, no
 * `sql.query`, no `file.read`, no `http.request` and no `shell.exec`. A job is a named operation
 * with a fixed parameter schema, not a channel for sending instructions.
 */
final class Jobs
{
    /**
     * Re-gather and report operational metadata now, rather than waiting for the next scheduled run.
     */
    public const INVENTORY_REFRESH = 'inventory.refresh';

    /**
     * Check for available Craft and plugin updates and report what is available.
     */
    public const UPDATES_CHECK = 'updates.check';

    /**
     * Take and verify a database backup.
     *
     * Declared so both sides agree on the spelling before it is implemented. It is **not** in
     * {@see self::available()}: the specification is explicit that restore, and by extension the
     * backup pipeline it belongs to, waits until its threat model, confirmation flow and failure
     * recovery have been designed and tested.
     */
    public const BACKUP_CREATE = 'backup.create';

    /**
     * Job types that may actually be enqueued and executed today.
     *
     * @return list<string>
     */
    public static function available(): array
    {
        return [
            self::INVENTORY_REFRESH,
            self::UPDATES_CHECK,
        ];
    }

    /**
     * Every job type the vocabulary reserves, implemented or not.
     *
     * @return list<string>
     */
    public static function reserved(): array
    {
        return [
            self::INVENTORY_REFRESH,
            self::UPDATES_CHECK,
            self::BACKUP_CREATE,
        ];
    }

    public static function isAvailable(string $type): bool
    {
        return in_array($type, self::available(), true);
    }

    // Job states, shared so the connector can reason about what it is told.
    // =========================================================================

    public const STATE_QUEUED = 'queued';

    public const STATE_CLAIMED = 'claimed';

    public const STATE_SUCCEEDED = 'succeeded';

    public const STATE_FAILED = 'failed';

    public const STATE_CANCELLED = 'cancelled';

    /** Claimed but never reported within its maximum runtime. */
    public const STATE_EXPIRED = 'expired';

    /**
     * States from which nothing further happens.
     *
     * @return list<string>
     */
    public static function terminalStates(): array
    {
        return [
            self::STATE_SUCCEEDED,
            self::STATE_FAILED,
            self::STATE_CANCELLED,
            self::STATE_EXPIRED,
        ];
    }

    /**
     * The most jobs a connector may be handed in one claim.
     *
     * Bounded so that a site returning from a long outage works through a backlog in batches rather
     * than being handed hundreds of jobs it will not finish before they expire.
     */
    public const MAX_CLAIM_BATCH = 5;
}
