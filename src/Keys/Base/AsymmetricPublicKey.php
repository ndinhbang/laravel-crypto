<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Base;

use Exception;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Contracts\ReceivingKey;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Key;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey as V4AsymmetricPublicKey;
use ParagonIE\Paseto\Protocol\Version4;
use TypeError;

use function hash_equals;

abstract class AsymmetricPublicKey extends Key implements ReceivingKey
{
    protected function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol
    ) {
        $this->key = $keyMaterial;
        $this->protocol = $protocol;
    }

    /**
     * Initialize a v4 public key.
     *
     * @throws Exception
     */
    public static function v4(string $keyMaterial): V4AsymmetricPublicKey
    {
        return new V4AsymmetricPublicKey($keyMaterial);
    }

    /**
     * Initialize a public key.
     *
     * @param string $keyMaterial
     * @param  ?ProtocolInterface $protocol
     *
     * @return AsymmetricPublicKey
     * @throws InvalidVersionException
     * @throws Exception
     */
    public static function newVersionKey(
        string $keyMaterial,
        ?ProtocolInterface $protocol = null
    ): self
    {
        $protocol = $protocol ?? new Version4();

        if (hash_equals($protocol::header(), Version4::HEADER)) {
            return new V4AsymmetricPublicKey($keyMaterial);
        }

        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * Returns the base64url-encoded public key.
     *
     * @throws TypeError
     * @throws PasetoException
     */
    abstract public function encode(): string;

    /**
     * Return a PEM-encoded public key
     */
    abstract public function encodePem(): string;

    /**
     * Initialize a public key from a base64url-encoded string.
     *
     * @throws Exception
     * @throws TypeError
     */
    public static function fromEncodedString(
        string $encoded,
        ?ProtocolInterface $version = null
    ): self
    {
        $version = $version ?? new Version4();

        if (hash_equals($version::header(), Version4::HEADER)) {
            return V4AsymmetricPublicKey::fromEncodedString($encoded, $version);
        }

        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @throws Exception
     */
    public static function importPem(string $pem, ?ProtocolInterface $protocol = null): self
    {
        $protocol = $protocol ?? new Version4();

        if ($protocol instanceof Version4) {
            return V4AsymmetricPublicKey::importPem($pem);
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    abstract public function toHexString(): string;



    public function isForVersion(ProtocolInterface $protocol): bool
    {
        return $this->protocol instanceof $protocol;
    }
}
