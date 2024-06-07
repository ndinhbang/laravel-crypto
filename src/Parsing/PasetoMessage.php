<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Parsing;

use ParagonIE\Paseto\Encoder\Base64UrlSafe;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\InvalidPurposeException;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\SecurityException;
use SodiumException;

use function count;
use function explode;

final class PasetoMessage
{
    private Header $header;

    private string $payload;

    private string $footer;

    public function __construct(Header $header, string $payload, string $footer)
    {
        $this->header = $header;
        $this->payload = $payload;
        $this->footer = $footer;
    }

    /**
     * Parse a string into a deconstructed PasetoMessage object.
     *
     * @param  string  $tainted  Tainted user-provided string.
     *
     * @throws InvalidVersionException
     * @throws InvalidPurposeException
     * @throws SecurityException
     * @throws SodiumException
     */
    public static function fromString(string $tainted): self
    {
        $pieces = explode('.', $tainted);
        $count = count($pieces);
        if ($count < 3 || $count > 4) {
            throw new SecurityException(
                'Truncated or invalid token',
                ExceptionCode::INVALID_NUMBER_OF_PIECES
            );
        }

        $header = new Header($pieces[0], $pieces[1]);
        $payload = Base64UrlSafe::decodeNoPadding($pieces[2]);
        $footer = $count > 3 ? Base64UrlSafe::decodeNoPadding($pieces[3]) : '';

        return new self($header, $payload, $footer);
    }

    public function header(): Header
    {
        return $this->header;
    }

    public function payload(): string
    {
        return $this->payload;
    }

    public function footer(): string
    {
        return $this->footer;
    }

    /**
     * @throws SodiumException
     */
    public function toString(): string
    {
        $message = $this->header->toString().
            Base64UrlSafe::encodeNoPadding($this->payload);

        if ($this->footer === '') {
            return $message;
        }

        return $message.'.'.Base64UrlSafe::encodeNoPadding($this->footer);
    }
}
