<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Traits;

trait RegisteredClaims
{
    /**
     * @var array<string, string>
     *
     * Adopted from JWT for usability
     */
    public array $registeredClaims = [
        'iss' => 'Issuer',
        'sub' => 'Subject',
        'aud' => 'Audience',
        'exp' => 'Expiration',
        'nbf' => 'Not Before',
        'iat' => 'Issued At',
        'jti' => 'Token Identifier',
    ];
}
