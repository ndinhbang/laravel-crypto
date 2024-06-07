<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Contracts;

use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;

interface ProtocolInterface
{
    /**
     * Must be constructable with no arguments so an instance may be passed
     * around in a type safe way.
     */
    public function __construct();

    /**
     * A unique header string with which the protocol can be identified.
     */
    public static function header(): string;

    /**
     * Does this protocol support implicit assertions?
     */
    public static function supportsImplicitAssertions(): bool;

    public static function generateAsymmetricSecretKey(): AsymmetricSecretKey;

    public static function generateSymmetricKey(): SymmetricKey;

    public static function getSymmetricKeyByteLength(): int;

    /**
     * Encrypt a message using a shared key.
     */
    public static function encrypt(
        string $data,
        SymmetricKey $key,
        string $footer = '',
        string $implicit = ''
    ): string;

    /**
     * Decrypt a message using a shared key.
     */
    public static function decrypt(
        string $data,
        SymmetricKey $key,
        ?string $footer = null,
        string $implicit = ''
    ): string;

    /**
     * Sign a message. Public-key digital signatures.
     */
    public static function sign(
        string $data,
        AsymmetricSecretKey $key,
        string $footer = '',
        string $implicit = ''
    ): string;

    /**
     * Verify a signed message. Public-key digital signatures.
     */
    public static function verify(
        string $signMsg,
        AsymmetricPublicKey $key,
        ?string $footer = null,
        string $implicit = ''
    ): string;
}
