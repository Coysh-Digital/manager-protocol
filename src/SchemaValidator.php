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
 * A small, strict validator for the subset of JSON Schema the protocol uses.
 *
 * Written by hand rather than pulled in as a dependency: this code runs on every inbound connector
 * payload and inside privileged plugin code on customer sites, so the spec asks for its
 * dependencies to be reviewed strictly. The supported subset is deliberately narrow - type, enum,
 * required, properties, additionalProperties, items, minimum, maximum, maxItems, maxLength and
 * pattern.
 *
 * The important behaviour is that `additionalProperties: false` **rejects** an unknown key rather
 * than stripping it. Silently dropping unrecognised fields would let a connector widen what it
 * collects without anyone noticing; failing loudly makes drift visible the moment it appears.
 */
final class SchemaValidator
{
    /**
     * @param array<string, mixed> $schema
     */
    public function __construct(private readonly array $schema)
    {
    }

    /**
     * Load a named schema shipped with this package.
     *
     * @throws ProtocolException
     */
    public static function forSchema(string $name): self
    {
        // Hyphens are permitted between segments so a schema can be named for the thing it describes
        // rather than for a namespace it does not have - `backup-manifest.v2` reads as what it is,
        // where `manifest.v2` would be ambiguous on the wire forever. The property this check exists
        // for is unchanged: no slash, no dot beyond the version separator, so no path to traverse.
        if (preg_match('~^[a-z0-9]+(-[a-z0-9]+)*\.v[0-9]+\z~', $name) !== 1) {
            throw new ProtocolException('Unknown schema name.');
        }

        $path = self::schemaDirectory() . '/' . $name . '.json';

        if (!is_file($path)) {
            throw new ProtocolException("No schema is registered for '{$name}'.");
        }

        $decoded = json_decode((string) file_get_contents($path), true);

        if (!is_array($decoded)) {
            throw new ProtocolException("Schema '{$name}' is not valid JSON.");
        }

        return new self($decoded);
    }

    /**
     * Absolute path to the directory holding the shipped schemas.
     */
    public static function schemaDirectory(): string
    {
        return dirname(__DIR__) . '/schemas';
    }

    /**
     * Validate a decoded payload.
     *
     * @param mixed $payload
     * @return list<string> Empty when valid; otherwise one message per problem, each naming the
     *                      offending path but never quoting its value.
     */
    public function validate(mixed $payload): array
    {
        $errors = [];

        $this->check($payload, $this->schema, '$', $errors);

        return $errors;
    }

    /**
     * Validate and throw on the first problem.
     *
     * @throws ProtocolException
     */
    public function assertValid(mixed $payload): void
    {
        $errors = $this->validate($payload);

        if ($errors !== []) {
            throw new ProtocolException('Payload rejected: ' . implode('; ', $errors));
        }
    }

    /**
     * @param array<string, mixed> $schema
     * @param list<string>         $errors
     */
    private function check(mixed $value, array $schema, string $path, array &$errors): void
    {
        if (isset($schema['type']) && !$this->matchesType($value, (string) $schema['type'])) {
            $errors[] = "{$path} must be of type {$schema['type']}";

            // Later constraints assume the type held, so stop descending here.
            return;
        }

        if (isset($schema['enum']) && is_array($schema['enum']) && !in_array($value, $schema['enum'], true)) {
            $errors[] = "{$path} is not one of the permitted values";
        }

        if (is_string($value)) {
            $this->checkString($value, $schema, $path, $errors);
        }

        // Both bounds, and floats as well as integers.
        //
        // `maximum` was absent until 1.1.0, which made it a trap rather than an omission: a schema
        // carrying one read as a guarantee and enforced nothing. `minimum` was checked on integers
        // only, so a negative float - a response time, say - passed a `"minimum": 0` untouched.
        if (is_int($value) || is_float($value)) {
            if (isset($schema['minimum']) && $value < $schema['minimum']) {
                $errors[] = "{$path} is below the permitted minimum";
            }

            if (isset($schema['maximum']) && $value > $schema['maximum']) {
                $errors[] = "{$path} is above the permitted maximum";
            }
        }

        if (is_array($value) && array_is_list($value)) {
            $this->checkArray($value, $schema, $path, $errors);
        }

        if (is_array($value) && !array_is_list($value)) {
            $this->checkObject($value, $schema, $path, $errors);
        }
    }

    /**
     * @param array<string, mixed> $schema
     * @param list<string>         $errors
     */
    private function checkString(string $value, array $schema, string $path, array &$errors): void
    {
        if (isset($schema['maxLength']) && mb_strlen($value) > (int) $schema['maxLength']) {
            $errors[] = "{$path} exceeds its maximum length";
        }

        if (isset($schema['pattern'])) {
            // Schema patterns are ECMA-flavoured and carry no delimiters, so one is added here.
            // "~" is safe: no protocol pattern contains it.
            if (preg_match('~' . $schema['pattern'] . '~u', $value) !== 1) {
                $errors[] = "{$path} does not match the permitted format";
            }
        }
    }

    /**
     * @param list<mixed>          $value
     * @param array<string, mixed> $schema
     * @param list<string>         $errors
     */
    private function checkArray(array $value, array $schema, string $path, array &$errors): void
    {
        if (isset($schema['maxItems']) && count($value) > (int) $schema['maxItems']) {
            $errors[] = "{$path} contains more items than permitted";
        }

        if (!isset($schema['items']) || !is_array($schema['items'])) {
            return;
        }

        foreach ($value as $index => $item) {
            $this->check($item, $schema['items'], "{$path}[{$index}]", $errors);
        }
    }

    /**
     * @param array<string, mixed> $value
     * @param array<string, mixed> $schema
     * @param list<string>         $errors
     */
    private function checkObject(array $value, array $schema, string $path, array &$errors): void
    {
        $properties = is_array($schema['properties'] ?? null) ? $schema['properties'] : [];

        foreach ($schema['required'] ?? [] as $required) {
            if (!array_key_exists($required, $value)) {
                $errors[] = "{$path}.{$required} is required";
            }
        }

        // The rule that matters: an unrecognised key is an error, not something to drop.
        if (($schema['additionalProperties'] ?? true) === false) {
            foreach (array_keys($value) as $key) {
                if (!array_key_exists($key, $properties)) {
                    $errors[] = "{$path}.{$key} is not a permitted field";
                }
            }
        }

        foreach ($properties as $key => $subSchema) {
            if (array_key_exists($key, $value) && is_array($subSchema)) {
                $this->check($value[$key], $subSchema, "{$path}.{$key}", $errors);
            }
        }
    }

    private function matchesType(mixed $value, string $type): bool
    {
        return match ($type) {
            'object' => is_array($value) && (!array_is_list($value) || $value === []),
            'array' => is_array($value) && array_is_list($value),
            'string' => is_string($value),
            // is_int() and is_float() both reject booleans, so `true` cannot satisfy a numeric
            // field the way a loose comparison would let it.
            'integer' => is_int($value),
            'number' => is_int($value) || is_float($value),
            'boolean' => is_bool($value),
            'null' => $value === null,
            default => true,
        };
    }
}
