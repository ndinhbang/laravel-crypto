<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Encoder;

use SodiumException;

abstract class Hex
{
    /**
     * Convert a binary string into a hexadecimal string without cache-timing leaks
     *
     * @param  string  $binString  (raw binary)
     *
     * @throws SodiumException
     */
    public static function encode(#[\SensitiveParameter] string $binString): string
    {
        return sodium_bin2hex($binString);
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing leaks
     *
     * @param  string  $encodedString
     * @return string (raw binary)
     *
     * @throws SodiumException
     */
    public static function decode(#[\SensitiveParameter] string $encodedString): string
    {
        return sodium_hex2bin($encodedString);
    }
}
