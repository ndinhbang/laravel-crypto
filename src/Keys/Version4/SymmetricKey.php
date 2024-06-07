<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Keys\Version4;

use ParagonIE\Paseto\Keys\SymmetricKey as BaseSymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;

class SymmetricKey extends BaseSymmetricKey
{
    public function __construct(
        #[\SensitiveParameter]
        string $keyMaterial
    ) {
        parent::__construct($keyMaterial, new Version4());
    }
}
