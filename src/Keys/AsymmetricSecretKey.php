<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys;

use Exception;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey as BaseAsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey as V4AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;

class AsymmetricSecretKey extends BaseAsymmetricSecretKey
{
    public function __construct(
        #[\SensitiveParameter]
        string $keyMaterial,
        ?ProtocolInterface $protocol = null
    ) {
        if (is_null($protocol)) {
            $protocol = new Version4();
        }
        parent::__construct($keyMaterial, $protocol);
    }

    /**
     * @throws Exception
     * @throws InvalidVersionException
     */
    public function encode(): string
    {
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricSecretKey($this->key))->encode();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @throws Exception
     * @throws InvalidVersionException
     * @throws PasetoException
     */
    public function encodePem(): string
    {
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricSecretKey($this->key))->encodePem();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }

    /**
     * @throws Exception
     * @throws InvalidVersionException
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        if ($this->protocol instanceof Version4) {
            return (new V4AsymmetricSecretKey($this->key))->getPublicKey();
        }
        throw new InvalidVersionException('Unexpected protocol version');
    }
}
