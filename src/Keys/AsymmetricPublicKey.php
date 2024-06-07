<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys;

use Exception;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey as BaseAsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey as V4AsymmetricPublicKey;
use ParagonIE\Paseto\Protocol\Version4;

class AsymmetricPublicKey extends BaseAsymmetricPublicKey
{
    public function __construct(
        string $keyMaterial,
        ProtocolInterface $protocol
    ) {
        parent::__construct($keyMaterial, $protocol);
    }

    /**
     * @throws Exception
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function encode(): string
    {
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricPublicKey($this->key))->encode();
        }
        throw new InvalidVersionException('Unexpected protocol version.');
    }

    /**
     * @throws Exception
     * @throws InvalidVersionException
     */
    public function encodePem(): string
    {
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricPublicKey($this->key))->encodePem();
        }
        throw new InvalidVersionException('Unexpected protocol version.');
    }

    /**
     * @throws Exception
     * @throws InvalidVersionException
     */
    public function toHexString(): string
    {
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricPublicKey($this->key))->toHexString();
        }
        throw new InvalidVersionException('Unexpected protocol version.');
    }
}
