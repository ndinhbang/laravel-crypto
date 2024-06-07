<?php

declare(strict_types=1);

namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Contracts\KeyRingInterface;
use ParagonIE\Paseto\Contracts\ReceivingKey;
use ParagonIE\Paseto\Exception\InvalidKeyException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Traits\MultiKeyTrait;

class ReceivingKeyRing implements KeyRingInterface, ReceivingKey
{
    use MultiKeyTrait;

    const KEY_TYPE = ReceivingKey::class;

    /** @var array<string, ReceivingKey> */
    protected array $keys = [];

    /**
     * Add a key to this KeyID.
     *
     * @return static
     *
     * @throws InvalidKeyException
     * @throws PasetoException
     */
    public function addKey(string $keyId, #[\SensitiveParameter] ReceivingKey $key): self
    {
        $this->typeCheckKey($key);
        $this->keys[$keyId] = $key;

        return $this;
    }
}
