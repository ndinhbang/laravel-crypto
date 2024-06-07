<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Base;

use Exception;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Contracts\ReceivingKey;
use ParagonIE\Paseto\Contracts\SendingKey;
use ParagonIE\Paseto\Encoder\Base64UrlSafe;
use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Key;
use ParagonIE\Paseto\Protocol\Version4;
use Random\RandomException;
use SodiumException;
use TypeError;

use function random_bytes;
use function sodium_crypto_generichash;

class SymmetricKey extends Key implements ReceivingKey, SendingKey
{
    const INFO_ENCRYPTION = 'paseto-encryption-key';

    const INFO_AUTHENTICATION = 'paseto-auth-key-for-aead';

    /**
     * @throws PasetoException
     */
    public function __construct(
        #[\SensitiveParameter]
        string $keyMaterial,
        ?ProtocolInterface $protocol = null
    ) {
        $this->protocol = $protocol ?? new Version4;

        switch ($this->protocol::class) {
            case Version4::class:
                if (Binary::safeStrlen($keyMaterial) !== Version4::SYMMETRIC_KEY_BYTES) {
                    throw new PasetoException('Invalid key length.');
                }
                break;
            default:
                throw new InvalidVersionException('Unsupported version', ExceptionCode::BAD_VERSION);
        }

        $this->key = $keyMaterial;
    }

    /**
     * @throws PasetoException
     * @throws RandomException
     */
    public static function generate(?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4;
        $length = $protocol::getSymmetricKeyByteLength();
        if ($length < 32) {
            throw new PasetoException('Invalid key length.');
        }

        return new self(
            random_bytes($length),
            $protocol
        );
    }

    /**
     * Initialize a v4 symmetric key.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function v4(#[\SensitiveParameter] string $keyMaterial): self
    {
        return new self($keyMaterial, new Version4());
    }

    /**
     * Return a base64url-encoded representation of this symmetric key.
     *
     * @throws SodiumException
     */
    public function encode(): string
    {
        return Base64UrlSafe::encodeNoPadding($this->key);
    }

    /**
     * Initialize a symmetric key from a base64url-encoded string.
     *
     * @throws SodiumException
     * @throws PasetoException
     */
    public static function fromEncodedString(#[\SensitiveParameter] string $encoded, ?ProtocolInterface $version = null): self
    {
        $decoded = Base64UrlSafe::decodeNoPadding($encoded);

        return new self($decoded, $version);
    }

    public function isForVersion(ProtocolInterface $protocol): bool
    {
        return $this->protocol instanceof $protocol;
    }

    /**
     * Split this key into two 256-bit keys and a nonce, using BLAKE2b-MAC
     * (with the given salt)
     *
     * @return array<int, string>
     *
     * @throws \SodiumException
     */
    public function splitV4(#[\SensitiveParameter] string $salt): array
    {
        $tmp = sodium_crypto_generichash(
            self::INFO_ENCRYPTION.$salt,
            $this->key,
            56
        );
        $encKey = Binary::safeSubstr($tmp, 0, 32);
        $nonce = Binary::safeSubstr($tmp, 32, 24);
        $authKey = sodium_crypto_generichash(
            self::INFO_AUTHENTICATION.$salt,
            $this->key
        );

        return [$encKey, $authKey, $nonce];
    }
}
