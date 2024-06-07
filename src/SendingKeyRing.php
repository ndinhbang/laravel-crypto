<?php

declare(strict_types=1);

namespace ParagonIE\Paseto;

use Exception;
use ParagonIE\Paseto\Contracts\KeyRingInterface;
use ParagonIE\Paseto\Contracts\SendingKey;
use ParagonIE\Paseto\Exception\InvalidKeyException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Traits\MultiKeyTrait;

class SendingKeyRing implements KeyRingInterface, SendingKey
{
    use MultiKeyTrait;

    const KEY_TYPE = SendingKey::class;

    /** @var array<string, SendingKey> */
    protected array $keys = [];

    /**
     * Add a key to this KeyID.
     *
     * @return static
     *
     * @throws InvalidKeyException
     * @throws PasetoException
     * @paslm-suppress PropertyTypeCoercion
     */
    public function addKey(string $keyId, #[\SensitiveParameter] SendingKey $key): self
    {
        $this->typeCheckKey($key);
        $this->keys[$keyId] = $key;

        return $this;
    }

    /**
     * Derive a keyring for receiving keys.
     *
     * @throws InvalidKeyException
     * @throws PasetoException
     * @throws Exception
     */
    public function deriveReceivingKeyRing(): ReceivingKeyRing
    {
        $ret = new ReceivingKeyRing();
        /**
         * @var SymmetricKey|AsymmetricSecretKey $key
         */
        foreach ($this->keys as $keyId => $key) {
            if ($key instanceof AsymmetricSecretKey) {
                $ret->addKey($keyId, $key->getPublicKey());
            } else {
                $ret->addKey($keyId, $key);
            }
        }

        return $ret;
    }
}
