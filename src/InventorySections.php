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
 * Which capability governs which part of an inventory report.
 *
 * Without this, `inventory:read` alone would carry everything - licence state, configuration flags,
 * queue depth - and the other read capabilities would be decorative. Granting `security:read` has to
 * change what a site actually sends, or the interface is describing a permission that does nothing.
 *
 * The connector omits sections it has not been granted. The platform's schema marks those sections
 * optional, so a report from a site holding only `inventory:read` validates perfectly well and simply
 * says less.
 *
 * Declared here rather than on either side, because both need the same answer: the connector to
 * decide what to send, and the platform to explain what a grant will reveal.
 */
final class InventorySections
{
    /**
     * Always present. Without these there is no report worth having, and none of them says anything
     * about the site beyond what it is running.
     *
     * @return list<string>
     */
    public static function core(): array
    {
        return ['schema_version', 'collected_at', 'connector', 'craft', 'php', 'database', 'environment'];
    }

    /**
     * Capability to the sections it unlocks.
     *
     * @return array<string, list<string>>
     */
    public static function map(): array
    {
        return [
            // What is installed. The plugin and package lists are here rather than under a narrower
            // capability because they are the same class of fact as the Craft version itself.
            'inventory:read' => ['plugins', 'composer_packages'],

            // Licence state, computed on the site. Never licence keys.
            'licences:read' => ['licence'],

            // Safe configuration booleans - dev mode, whether HTTPS is enforced. Separate because
            // these are the facts a finding is derived from, and an operator may reasonably want the
            // version inventory without them.
            'security:read' => ['config_flags'],

            // Operational depth: queue counts and migration state.
            'system:read' => ['queue', 'migrations'],
        ];
    }

    /**
     * The sections a site holding these capabilities may send.
     *
     * @param  list<string>  $capabilities
     * @return list<string>
     */
    public static function permitted(array $capabilities): array
    {
        $sections = self::core();

        foreach (self::map() as $capability => $granted) {
            if (in_array($capability, $capabilities, true)) {
                $sections = [...$sections, ...$granted];
            }
        }

        return $sections;
    }

    /**
     * Which capability a section needs, if any.
     */
    public static function capabilityFor(string $section): ?string
    {
        foreach (self::map() as $capability => $sections) {
            if (in_array($section, $sections, true)) {
                return $capability;
            }
        }

        return null;
    }

    /**
     * Strip anything the given capabilities do not cover.
     *
     * Used by the connector before sending. The platform validates the result against the schema and
     * would accept the fuller payload too - this is the site declining to send what it was not asked
     * for, which is the right place for that decision.
     *
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $capabilities
     * @return array<string, mixed>
     */
    public static function filter(array $payload, array $capabilities): array
    {
        $permitted = self::permitted($capabilities);

        return array_filter(
            $payload,
            static fn (string $key): bool => in_array($key, $permitted, true),
            ARRAY_FILTER_USE_KEY,
        );
    }
}
