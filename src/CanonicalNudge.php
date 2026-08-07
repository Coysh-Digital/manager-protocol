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
 * The canonical string the platform signs when it asks a site to check in now.
 *
 * This is the one thing the platform initiates. Everywhere else in this protocol the connector calls
 * out and the platform answers; a nudge is the platform knocking, and the site deciding what to do
 * about it.
 *
 * **Its entire vocabulary is "poll".** There is no field here for a job, a command, a path on the
 * site, a capability or a destination, and that is the design rather than an omission - a site that
 * receives a nudge does exactly what it would have done on its own schedule a few minutes later, which
 * is to make an ordinary signed claim request and find out for itself what work is waiting. So the
 * worst a forged or replayed nudge can achieve is an early poll. Every decision that matters - whether
 * a capability is still granted, which recipients an artifact may be sealed to, where an upload may go
 * - is made after that claim, by code this class cannot reach.
 *
 * A second kind of nudge would need a second prefix, which is a change to this package and a moved
 * fixture. The vocabulary is held to one word by the wire format, not by a comment asking nicely.
 *
 * Three fields, and each earns its place:
 *
 * - `siteId` binds the signature to one installation, so a nudge captured from one site cannot be
 *   aimed at another.
 * - `timestamp` bounds how long a captured nudge stays useful, to {@see Protocol::DEFAULT_TIMESTAMP_TOLERANCE}.
 * - `nonce` is what the receiver claims to refuse the second delivery of the same one.
 *
 * What is deliberately absent is the request path. A Craft site's action URL varies with
 * `actionTrigger`, `headlessMode`, `omitScriptNameInUrls` and whether the install sits in a subfolder,
 * and anything in front of it may rewrite what finally arrives. Signing a path would therefore fail on
 * sites that are behaving perfectly, in exchange for no authority - `siteId` already says which
 * installation this is for, and the endpoint does only one thing.
 *
 * There is no body-hash field either, because there is no body. The canonical string having nowhere to
 * put one is a stronger guarantee than hashing an empty string would be: a body cannot be smuggled in
 * later without changing the protocol.
 */
final class CanonicalNudge
{
    public function __construct(
        public readonly string $siteId,
        public readonly int $timestamp,
        public readonly string $nonce,
    ) {
    }

    public function toString(): string
    {
        return implode("\n", [
            Protocol::NUDGE_PREFIX,
            $this->siteId,
            (string) $this->timestamp,
            $this->nonce,
        ]);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * Sign this nudge with the platform's secret key.
     *
     * The same key that signs a claim response. A nudge grants nothing a claim response does not
     * already grant, so a separate key would be a second thing to rotate and protect in exchange for
     * no reduction in what a stolen key could do.
     */
    public function sign(string $secretKeyBase64): string
    {
        return Keys::sign($this->toString(), $secretKeyBase64);
    }

    /**
     * Verify a nudge signature against the platform's public key.
     *
     * The connector calls this with the key it pinned at pairing - never with a key from the request.
     * A nudge that does not verify must be refused outright: falling back to "well, poll anyway" would
     * hand an unauthenticated caller the one effect the endpoint has.
     */
    public function verify(string $signatureBase64, string $publicKeyBase64): bool
    {
        return Keys::verify($this->toString(), $signatureBase64, $publicKeyBase64);
    }
}
