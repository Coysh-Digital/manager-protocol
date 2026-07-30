<?php

declare(strict_types=1);

/**
 * Read a fixture as a decoded array.
 *
 * @return array<string, mixed>
 */
function fixture(string $relativePath): array
{
    /** @var array<string, mixed> $decoded */
    $decoded = json_decode(fixtureBytes($relativePath), true, 512, JSON_THROW_ON_ERROR);

    return $decoded;
}

/**
 * Read a fixture as raw bytes.
 *
 * Needed because two of the backup fixtures are not documents to be decoded: `envelope.v2/artifact.bin`
 * is a binary file, and `backup-manifest.v2/valid.json` is the exact byte sequence a signature covers.
 * Decoding and re-encoding either of them would test a different object from the one that shipped.
 */
function fixtureBytes(string $relativePath): string
{
    $path = dirname(__DIR__) . '/fixtures/' . $relativePath;

    expect($path)->toBeFile();

    return (string) file_get_contents($path);
}
