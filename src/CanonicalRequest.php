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
 * The canonical string a connector signs, and the platform reconstructs to verify.
 *
 * Both sides must build this identically from the same inputs, so the format is fixed here rather
 * than in either application. Every field that affects the meaning of a request is covered: change
 * the method, the path, the body or the timing and the signature no longer verifies.
 */
final class CanonicalRequest
{
    public function __construct(
        public readonly string $siteId,
        public readonly string $connectorVersion,
        public readonly int $timestamp,
        public readonly string $nonce,
        public readonly string $method,
        public readonly string $path,
        public readonly string $body,

        /**
         * A body hash declared instead of computed, for a body too large to hold.
         *
         * An artifact upload cannot be hashed after the fact and then judged: by then it has already
         * been read. So the sender declares the hash, the signature covers the declaration, and the
         * receiver authenticates before reading a byte — then compares the stream against a promise
         * made before it started.
         */
        public readonly ?string $declaredBodyHash = null,
    ) {
    }

    /**
     * A request whose body is streamed rather than held.
     *
     * Produces the same canonical string a buffered request with identical content would, which is the
     * property that matters: there is one signing format, not one per transport.
     */
    public static function forStream(
        string $siteId,
        string $connectorVersion,
        int $timestamp,
        string $nonce,
        string $method,
        string $path,
        string $bodyHash,
    ): self {
        return new self(
            siteId: $siteId,
            connectorVersion: $connectorVersion,
            timestamp: $timestamp,
            nonce: $nonce,
            method: $method,
            path: $path,
            body: '',
            declaredBodyHash: $bodyHash,
        );
    }

    /**
     * Hex SHA-256 of the raw body bytes.
     *
     * An empty body hashes normally rather than being special-cased, so a body cannot be dropped
     * without invalidating the signature.
     */
    public function bodyHash(): string
    {
        return $this->declaredBodyHash ?? hash('sha256', $this->body);
    }

    /**
     * The exact bytes that get signed.
     */
    public function toString(): string
    {
        return implode("\n", [
            Protocol::REQUEST_PREFIX,
            $this->siteId,
            $this->connectorVersion,
            (string) $this->timestamp,
            $this->nonce,
            strtoupper($this->method),
            $this->path,
            $this->bodyHash(),
        ]);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Sign this request with a connector's secret key.
     */
    public function sign(string $secretKeyBase64): string
    {
        return Keys::sign($this->toString(), $secretKeyBase64);
    }

    /**
     * Verify a signature against a connector's public key.
     */
    public function verify(string $signatureBase64, string $publicKeyBase64): bool
    {
        return Keys::verify($this->toString(), $signatureBase64, $publicKeyBase64);
    }

    /**
     * Normalise a request path and query into the single string that gets signed.
     *
     * The query is sorted by name and then value so that two orderings of the same parameters
     * produce one canonical form, and a reverse proxy reordering them cannot break verification.
     * Signing the query means it cannot be tampered with in transit either.
     *
     * @param array<string, scalar|list<scalar>> $query
     */
    public static function canonicalPath(string $path, array $query = []): string
    {
        $path = '/' . ltrim($path, '/');

        if ($query === []) {
            return $path;
        }

        $pairs = [];

        foreach ($query as $name => $value) {
            foreach (is_array($value) ? $value : [$value] as $single) {
                $pairs[] = rawurlencode((string) $name) . '=' . rawurlencode((string) $single);
            }
        }

        sort($pairs, SORT_STRING);

        return $path . '?' . implode('&', $pairs);
    }
}
