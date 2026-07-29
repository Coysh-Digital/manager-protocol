<?php

/**
 * Manager protocol.
 *
 * @link      https://coysh.digital
 * @copyright Copyright (c) Coysh Digital
 */

declare(strict_types=1);

namespace coyshdigital\managerprotocol;

use RuntimeException;

/**
 * Raised when input does not conform to the protocol.
 *
 * Messages describe the shape of the problem and never echo the offending value, because these
 * strings reach logs and a rejected payload may carry key material.
 */
class ProtocolException extends RuntimeException
{
}
