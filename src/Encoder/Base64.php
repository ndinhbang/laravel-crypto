<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Encoder;

abstract class Base64
{
    /**
     * Encode into Base64
     *
     * Base64 character set "[A-Z][a-z][0-9]+/"
     *
     * @param string $binString
     *
     * @return string
     * @throws \SodiumException
     */
    public static function encode(#[\SensitiveParameter] string $binString): string
    {
        return sodium_bin2base64($binString, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    /**
     * Encode into Base64, no = padding
     *
     * Base64 character set "[A-Z][a-z][0-9]+/"
     *
     * @param string $src
     *
     * @return string
     * @throws \SodiumException
     */
    public static function encodeNoPadding(#[\SensitiveParameter] string $src): string
    {
        return sodium_bin2base64($src, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * decode from base64 into binary
     *
     * Base64 character set "./[A-Z][a-z][0-9]"
     *
     * @param string $encodedString
     * @param bool $noPadding
     * @return string
     * @throws \SodiumException
     */
    public static function decode(#[\SensitiveParameter] string $encodedString, bool $noPadding = false): string
    {
        if ($noPadding) {
            return sodium_base642bin($encodedString, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        }

        return sodium_base642bin($encodedString, SODIUM_BASE64_VARIANT_ORIGINAL);
    }

    /**
     * @param string $encodedString
     *
     * @return string
     * @throws \SodiumException
     */
    public static function decodeNoPadding(#[\SensitiveParameter] string $encodedString): string
    {
        return static::decode($encodedString, true);
    }
}
