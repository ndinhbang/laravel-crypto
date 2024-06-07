<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Version4;

use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Encoder\Base64;
use ParagonIE\Paseto\Encoder\Base64UrlSafe;
use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Encoder\Hex;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey as BasePublicKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Util;

use function str_replace;
use function strlen;
use function strtok;
use function substr;

class AsymmetricPublicKey extends BasePublicKey
{
    private const PEM_ENCODE_PREFIX = '302a300506032b6570032100';

    /**
     * @throws PasetoException
     * @throws \SodiumException
     */
    public function __construct(string $keyData)
    {
        $len = Binary::safeStrlen($keyData);
        if ($len === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES << 1) {
            // Try hex-decoding
            $keyData = Hex::decode($keyData);
        } elseif ($len !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new PasetoException(
                'Public keys must be 32 bytes long; '.$len.' given.',
                ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
            );
        }

        parent::__construct($keyData, new Version4());
    }

    /**
     * @throws \SodiumException
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeNoPadding($this->key);
    }

    /**
     * @throws \SodiumException
     */
    public function encodePem(): string
    {
        $encoded = Base64::encode(
            Hex::decode(self::PEM_ENCODE_PREFIX).$this->raw()
        );

        return "-----BEGIN PUBLIC KEY-----\n".
            Util::dos2unix(chunk_split($encoded, 64)).
            '-----END PUBLIC KEY-----';
    }

    /**
     * @throws PasetoException
     * @throws \SodiumException
     */
    public static function fromEncodedString(
        string $encoded,
        ?ProtocolInterface $version = null
    ): self {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);

        return new self($decoded);
    }

    /**
     * @throws \SodiumException
     */
    public function toHexString(): string
    {
        return Hex::encode($this->key);
    }

    /**
     * @throws PasetoException
     * @throws \SodiumException
     */
    public static function importPem(string $pem, ?ProtocolInterface $protocol = null): self
    {
        $formattedKey = str_replace('-----BEGIN PUBLIC KEY-----', '', $pem);
        $formattedKey = str_replace('-----END PUBLIC KEY-----', '', $formattedKey);
        $key = Base64::decode(strtok($formattedKey, "\n"));
        $prefix = Hex::decode(self::PEM_ENCODE_PREFIX);

        return new self(substr($key, strlen($prefix)));
    }
}
