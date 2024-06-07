<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Contracts\ValidationRuleInterface;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;

use function hash_equals;

class Subject implements ValidationRuleInterface
{
    protected string $failure = 'OK';

    protected string $subject;

    public function __construct(string $subject)
    {
        $this->subject = $subject;
    }

    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * Does the 'sub' claim match what we expect from the Parser?
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $subject = $token->getSubject();
            if (! hash_equals($this->subject, $subject)) {
                $this->failure = 'This token was not related to '.
                    $this->subject.' (expected); its subject is '.
                    $subject.' instead.';

                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();

            return false;
        }

        return true;
    }
}
