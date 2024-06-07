<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Contracts\ValidationRuleInterface;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;

use function hash_equals;

class IssuedBy implements ValidationRuleInterface
{
    protected string $failure = 'OK';

    protected string $issuer;

    /**
     * IssuedBy constructor.
     */
    public function __construct(string $issuer)
    {
        $this->issuer = $issuer;
    }

    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * Does the 'iss' claim match what we expect from the Parser?
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $issuedBy = $token->getIssuer();
            if (! hash_equals($this->issuer, $issuedBy)) {
                $this->failure = 'This token was not issued by '.
                    $this->issuer.' (expected); it was issued by '.
                    $issuedBy.' instead.';

                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();

            return false;
        }

        return true;
    }
}
