<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Parsing;

trait NonExpiringSupport
{
    protected bool $nonExpiring = false;

    /**
     * Do not set an expiration header by default.
     */
    public function setNonExpiring(bool $nonExpiring): static
    {
        $this->nonExpiring = $nonExpiring;

        return $this;
    }
}
