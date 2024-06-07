<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Rules;

use DateTime;
use DateTimeInterface;
use Exception;
use ParagonIE\Paseto\Contracts\ValidationRuleInterface;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;

class ValidAt implements ValidationRuleInterface
{
    protected string $failure = 'OK';

    protected DateTimeInterface $now;

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
     * @throws Exception
     */
    public function isValid(JsonToken $token): bool
    {
        try {
            $issuedAt = $token->getIssuedAt();
            if ($issuedAt > $this->now) {
                $this->failure = 'This token was issued in the future.';

                return false;
            }
            $notBefore = $token->getNotBefore();
            if ($notBefore > $this->now) {
                $this->failure = 'This token cannot be used yet.';

                return false;
            }
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
