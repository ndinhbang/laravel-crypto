<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Contracts;

interface KeyInterface
{
    /**
     * The intended version for this protocol. Currently only meaningful
     * in asymmetric cryptography.
     */
    public function getProtocol(): ProtocolInterface;

    /**
     * Returns the raw key as a string.
     */
    public function raw(): string;

    /**
     * This hides the internal state from var_dump(), etc. if it returns
     * an empty array.
     *
     * @return array
     */
    public function __debugInfo();
}
