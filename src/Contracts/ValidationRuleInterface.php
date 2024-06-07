<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Contracts;

use ParagonIE\Paseto\JsonToken;

interface ValidationRuleInterface
{
    /**
     * Get the message of the last failure. Optional.
     */
    public function getFailureMessage(): string;

    /**
     * Validate this token according to this rule.
     */
    public function isValid(JsonToken $token): bool;
}
