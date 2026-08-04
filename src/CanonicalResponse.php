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
 * The canonical string the platform signs when a response carries commands or security-sensitive
 * configuration.
 *
 * The request nonce is part of the signed material, which binds a response to the single request
 * that asked for it. Without that binding a captured response - say, one granting a capability —
 * could be replayed at the connector against a later request.
 */
final class CanonicalResponse
{
    public function __construct(
        public readonly string $siteId,
        public readonly string $requestNonce,
        public readonly int $status,
        public readonly string $body,
    ) {
    }

    public function bodyHash(): string
    {
        return hash('sha256', $this->body);
    }

    public function toString(): string
    {
        return implode("\n", [
            Protocol::RESPONSE_PREFIX,
            $this->siteId,
            $this->requestNonce,
            (string) $this->status,
            $this->bodyHash(),
        ]);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Sign this response with the platform's secret key.
     */
    public function sign(string $secretKeyBase64): string
    {
        return Keys::sign($this->toString(), $secretKeyBase64);
    }

    /**
     * Verify a response signature against the platform's public key.
     *
     * The connector calls this on every response that should be signed. A missing or bad signature
     * must be treated as a failed request, never as an unsigned success.
     */
    public function verify(string $signatureBase64, string $publicKeyBase64): bool
    {
        return Keys::verify($this->toString(), $signatureBase64, $publicKeyBase64);
    }
}
