<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Contracts\ValidationRuleInterface;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;

use function hash_equals;

class ForAudience implements ValidationRuleInterface
{
    protected string $failure = 'OK';

    protected string $audience;

    public function __construct(string $audience)
    {
        $this->audience = $audience;
    }

    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * Does the 'aud' claim match what we expect from the Parser?
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $audience = $token->getAudience();
            if (! hash_equals($this->audience, $audience)) {
                $this->failure = 'This token is not intended for '.
                    $this->audience.' (expected); instead, it is intended for '.
                    $audience.' instead.';

                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();

            return false;
        }

        return true;
    }
}
