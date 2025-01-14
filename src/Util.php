<?php

declare(strict_types=1);

namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Encoder\Base64UrlSafe;
use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Exception\EncodingException;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\PasetoException;
use SodiumException;

use function array_pop;
use function array_slice;
use function count;
use function explode;
use function hash_equals;
use function implode;
use function pack;
use function preg_match_all;
use function preg_replace;
use function sodium_memzero;
use function str_replace;

abstract class Util
{
    /**
     * Calculate the depth of a JSON string without passing it to json_decode()
     *
     * @throws EncodingException
     */
    public static function calculateJsonDepth(string $json): int
    {
        // Remove quotes quotes first:
        $stripped = str_replace('\"', '', $json);

        // Remove whitespace:
        $stripped = preg_replace('/\s+/', '', $stripped);

        // Strip everything out of quotes:
        $stripped = preg_replace('#"[^"]+"([:,}\]])#', '$1', $stripped);

        // Remove everything that isn't a map or list definition
        $stripped = preg_replace('#[^\[\]{}]#', '', $stripped);

        $previous = '';
        $depth = 1;
        /** @psalm-suppress RiskyTruthyFalsyComparison */
        while (! empty($stripped) && $stripped !== $previous) {
            $previous = $stripped;
            // Remove pairs of tokens
            $stripped = str_replace(['[]', '{}'], [], $stripped);
            $depth++;
        }
        /** @psalm-suppress RiskyTruthyFalsyComparison */
        if (! empty($stripped)) {
            throw new EncodingException(
                'Invalid JSON string provided',
                ExceptionCode::INVALID_JSON
            );
        }

        return $depth;
    }

    /**
     * Count the number of instances of `":` without a preceding backslash.
     */
    public static function countJsonKeys(string $json): int
    {
        return preg_match_all('#[^\\\]":#', $json);
    }

    /**
     * Normalize line-endings to UNIX-style (LF rather than CRLF).
     */
    public static function dos2unix(#[\SensitiveParameter] string $in): string
    {
        return str_replace("\r\n", "\n", $in);
    }

    public static function longToBytes(#[\SensitiveParameter] int $long): string
    {
        return pack('P', $long);
    }

    /**
     * Format the Additional Associated Data.
     *
     * Prefix with the length (64-bit unsigned little-endian integer)
     * followed by each message. This provides a more explicit domain
     * separation between each piece of the message.
     *
     * Each length is masked with PHP_INT_MAX using bitwise AND (&) to
     * clear out the MSB of the total string length.
     */
    public static function preAuthEncode(string ...$pieces): string
    {
        $accumulator = self::longToBytes(count($pieces) & PHP_INT_MAX);
        foreach ($pieces as $piece) {
            $len = Binary::safeStrlen($piece);
            $accumulator .= self::longToBytes($len & PHP_INT_MAX);
            $accumulator .= $piece;
        }

        return $accumulator;
    }

    /**
     * If a footer was included with the message, extract it.
     * Otherwise, return an empty string.
     *
     * @throws SodiumException
     */
    public static function extractFooter(string $payload): string
    {
        $pieces = explode('.', $payload);
        if (count($pieces) > 3) {
            return Base64UrlSafe::decodeNoPadding(array_pop($pieces));
        }

        return '';
    }

    /**
     * If a footer was included with the message, remove it.
     */
    public static function removeFooter(string $payload): string
    {
        $pieces = explode('.', $payload);
        if (count($pieces) > 3) {
            return implode('.', array_slice($pieces, 0, 3));
        }

        return $payload;
    }

    /**
     * If a footer was included with the message, first verify that
     * it's equivalent to the one we expect, then remove it from the token payload.
     *
     * @throws PasetoException
     * @throws SodiumException
     */
    public static function validateAndRemoveFooter(
        string $payload,
        string $footer = ''
    ): string
    {
        if (empty($footer)) {
            return $payload;
        }
        $footer = Base64UrlSafe::encodeNoPadding($footer);
        $payload_len = Binary::safeStrlen($payload);
        $footer_len = Binary::safeStrlen($footer) + 1;

        $trailing = Binary::safeSubstr(
            $payload,
            $payload_len - $footer_len,
            $footer_len
        );
        if (! hash_equals('.'.$footer, $trailing)) {
            throw new PasetoException(
                'Invalid message footer.',
                ExceptionCode::FOOTER_MISMATCH_EXPECTED
            );
        }

        return Binary::safeSubstr($payload, 0, $payload_len - $footer_len);
    }

    /**
     * Wipe this value from memory.
     *
     * @param-out ?string $byRef
     */
    public static function wipe(string &$byRef): void
    {
        try {
            sodium_memzero($byRef);
        } catch (SodiumException $ex) {
            $byRef ^= $byRef;
            unset($byRef);
        }
    }
}
