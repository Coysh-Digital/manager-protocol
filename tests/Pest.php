<?php

declare(strict_types=1);

/**
 * Read a fixture as a decoded array.
 *
 * @return array<string, mixed>
 */
function fixture(string $relativePath): array
{
    $path = dirname(__DIR__) . '/fixtures/' . $relativePath;

    expect($path)->toBeFile();

    /** @var array<string, mixed> $decoded */
    $decoded = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    return $decoded;
}
