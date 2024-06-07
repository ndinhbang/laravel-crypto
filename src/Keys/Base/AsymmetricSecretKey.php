<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Base;

use Exception;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Contracts\SendingKey;
use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Exception\SecurityException;
use ParagonIE\Paseto\Key;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey as V4AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Util;
use SodiumException;
use TypeError;

use function hash_equals;
use function sodium_crypto_sign_seed_keypair;

abstract class AsymmetricSecretKey extends Key implements SendingKey
{
    protected bool $hasAssertedValid = false;

    protected function __construct(
        #[\SensitiveParameter]
        string $keyMaterial,
        ProtocolInterface $protocol
    ) {
        $this->key = $keyMaterial;
        $this->protocol = $protocol;
    }

    public function hasAssertedSecretKeyValid(): bool
    {
        return $this->hasAssertedValid;
    }

    /**
     * Optional check for libraries that load keys from semi-trustworthy sources.
     *
     * Misuse-resistance: Prevent mismatched public keys
     * See: https://github.com/MystenLabs/ed25519-unsafe-libs
     *
     * @throws SecurityException
     * @throws SodiumException
     */
    public function assertSecretKeyValid(): void
    {
        if (! ($this->protocol instanceof Version4)) {
            return;
        }
        $sk = Binary::safeSubstr(
            sodium_crypto_sign_seed_keypair(
                Binary::safeSubstr($this->key, 0, 32)
            ),
            0,
            64
        );
        if (! hash_equals($this->key, $sk)) {
            throw new SecurityException(
                'Key mismatch: Public key does not belong to private key.'
            );
        }
        $this->hasAssertedValid = true;
    }

    /**
     * Initialize a v4 secret key.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function v4(#[\SensitiveParameter] string $keyMaterial): V4AsymmetricSecretKey
    {
        return new V4AsymmetricSecretKey($keyMaterial);
    }

    /**
     * Generate a secret key.
     *
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function generate(?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4;

        return V4AsymmetricSecretKey::generate($protocol);
    }

    /**
     * Initialize a public key.
     *
     * @throws InvalidVersionException
     * @throws Exception
     */
    public static function newVersionKey(
        #[\SensitiveParameter]
        string $keyMaterial,
        ?ProtocolInterface $protocol = null
    ): self
    {
        $protocol = $protocol ?? new Version4();

        if (hash_equals($protocol::header(), Version4::HEADER)) {
            return new V4AsymmetricSecretKey($keyMaterial);
        }

        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * Return a base64url-encoded representation of this secret key.
     *
     * @throws SodiumException
     */
    abstract public function encode(): string;

    /**
     * Return a PEM-encoded secret key
     *
     * @throws PasetoException
     */
    abstract public function encodePem(): string;

    /**
     * Initialize a secret key from a base64url-encoded string.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function fromEncodedString(#[\SensitiveParameter] string $encoded, ?ProtocolInterface $version = null): self
    {
        if ($version && hash_equals($version::header(), Version4::HEADER)) {
            return V4AsymmetricSecretKey::fromEncodedString($encoded);
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @throws Exception
     */
    public static function importPem(#[\SensitiveParameter] string $pem, ?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4();

        if ($protocol instanceof Version4) {
            return V4AsymmetricSecretKey::importPem($pem);
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    public function isForVersion(ProtocolInterface $protocol): bool
    {
        return $this->protocol instanceof $protocol;
    }

    /**
     * Get the public key that corresponds to this secret key.
     *
     * @throws Exception
     * @throws TypeError
     */
    abstract public function getPublicKey(): AsymmetricPublicKey;

    /**
     * Get the raw key contents.
     */
    public function raw(): string
    {
        return Util::dos2unix($this->key);
    }
}
