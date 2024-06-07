<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Version4;

use Exception;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Encoder\Base64;
use ParagonIE\Paseto\Encoder\Base64UrlSafe;
use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Encoder\Hex;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey as BaseSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Util;
use TypeError;

use function str_replace;
use function strlen;
use function strtok;
use function substr;

class AsymmetricSecretKey extends BaseSecretKey
{
    private const PEM_ENCODE_PREFIX = '302e020100300506032b657004220420';

    /**
     * @throws Exception
     * @throws TypeError
     */
    public function __construct(#[\SensitiveParameter] string $keyData)
    {
        $len = Binary::safeStrlen($keyData);
        if ($len === SODIUM_CRYPTO_SIGN_KEYPAIRBYTES) {
            $keyData = Binary::safeSubstr($keyData, 0, 64);
        } elseif ($len !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            if ($len !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                throw new PasetoException(
                    'Secret keys must be 32 or 64 bytes long; '.$len.' given.',
                    ExceptionCode::UNSPECIFIED_CRYPTOGRAPHIC_ERROR
                );
            }
            $keypair = sodium_crypto_sign_seed_keypair($keyData);
            $keyData = Binary::safeSubstr($keypair, 0, 64);
        }

        parent::__construct($keyData, new Version4());
    }

    /**
     * @throws \SodiumException
     */
    public static function generate(?ProtocolInterface $protocol = null): self
    {
        return new self(
            sodium_crypto_sign_secretkey(
                sodium_crypto_sign_keypair()
            )
        );
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

        return "-----BEGIN EC PRIVATE KEY-----\n".
            Util::dos2unix(chunk_split($encoded, 64)).
            '-----END EC PRIVATE KEY-----';
    }

    /**
     * @throws \SodiumException
     */
    public static function fromEncodedString(#[\SensitiveParameter] string $encoded, ?ProtocolInterface $version = null): self
    {
        return new self(Base64UrlSafe::decodeNoPadding($encoded));
    }

    /**
     * @throws \SodiumException
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        return new AsymmetricPublicKey(
            sodium_crypto_sign_publickey_from_secretkey($this->key)
        );
    }

    /**
     * @throws \SodiumException
     */
    public static function importPem(#[\SensitiveParameter] string $pem, ?ProtocolInterface $protocol = null): self
    {
        $formattedKey = str_replace('-----BEGIN EC PRIVATE KEY-----', '', $pem);
        $formattedKey = str_replace('-----END EC PRIVATE KEY-----', '', $formattedKey);
        $key = Base64::decode(strtok($formattedKey, "\n"));
        $prefix = Hex::decode(self::PEM_ENCODE_PREFIX);

        return new self(substr($key, strlen($prefix)));
    }
}
