<?php
declare(strict_types=1);
namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Exception\KeyMisuseException;

abstract class Key
{
    protected string $key;

    protected ProtocolInterface $protocol;

    /**
     * @throws KeyMisuseException
     * @codeCoverageIgnore
     */
    final public function __clone()
    {
        throw new KeyMisuseException(
            'This key object cannot be cloned.'
        );
    }

    /**
     * Hide this from var_dump(), etc.
     *
     * @return array
     * @codeCoverageIgnore
     */
    final public function __debugInfo()
    {
        return [];
    }

    /**
     * Wipe secrets before freeing memory
     */
    final public function __destruct()
    {
        Util::wipe($this->key);
    }

    /**
     * @throws KeyMisuseException
     * @codeCoverageIgnore
     */
    final public function __sleep()
    {
        throw new KeyMisuseException(
            'This key object cannot be serialized.'
        );
    }

    /**
     * @throws KeyMisuseException
     * @codeCoverageIgnore
     */
    final public function __wakeup()
    {
        throw new KeyMisuseException(
            'This key object cannot be unserialized.'
        );
    }

    /**
     * Don't allow this object to ever be unserialized
     * @throws KeyMisuseException
     * @codeCoverageIgnore
     */
    final public function __toString()
    {
        throw new KeyMisuseException(
            'This key object cannot be inlined as a string.'
        );
    }

    /**
     * Get the raw key contents.
     */
    public function raw(): string
    {
        return $this->key;
    }

    /**
     * Get the version of PASETO that this key is intended for.
     */
    public function getProtocol(): ProtocolInterface
    {
        return $this->protocol;
    }
}
