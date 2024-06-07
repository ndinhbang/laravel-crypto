<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Rules;

use DateTime;
use DateTimeInterface;
use Exception;
use ParagonIE\Paseto\Contracts\ValidationRuleInterface;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;

class NotExpired implements ValidationRuleInterface
{
    protected string $failure = 'OK';

    protected DateTimeInterface $now;

    /**
     * @param  DateTimeInterface|null  $now  Allows "now" to be overwritten for unit testing
     */
    public function __construct(?DateTimeInterface $now = null)
    {
        if (! $now) {
            $now = new DateTime();
        }
        $this->now = $now;
    }

    public function getFailureMessage(): string
    {
        return $this->failure;
    }

    /**
     * Does the 'exp' claim match what we expect from the Parser
     * (i.e. not the future)?
     *
     *
     * @throws Exception
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $expires = $token->getExpiration();
            if ($expires < $this->now) {
                $this->failure = 'This token has expired.';

                return false;
            }
        } catch (PasetoException $ex) {
            $this->failure = $ex->getMessage();

            return false;
        }

        return true;
    }
}
