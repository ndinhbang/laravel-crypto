<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Exception;

use ParagonIE\Corner\Exception;
use Throwable;

class PasetoException extends Exception
{
    /**
     * @param string $message
     * @param int $code
     * @param \Throwable|null $previous
     */
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->setHelpfulMessage(ExceptionCode::explainErrorCode($code));
    }
}
