<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Rules;

use ParagonIE\Paseto\Contracts\ValidationRuleInterface;
use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Exception\EncodingException;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Util;
use RangeException;

use function is_array;
use function json_decode;
use function json_last_error_msg;

class FooterJSON implements ValidationRuleInterface
{
    /** @var int<1, 2147483647> */
    protected int $maxDepth;

    protected int $maxKeys;

    protected int $maxLength;

    protected string $rejectReason = '';

    public function __construct(int $maxDepth = 2, int $maxLength = 8192, int $maxKeys = 512)
    {
        if ($maxDepth < 1 || $maxDepth > 0x7FFF_FFFF) {
            throw new RangeException('Max depth parameter is too large.');
        }
        $this->maxDepth = $maxDepth;
        $this->maxKeys = $maxKeys;
        $this->maxLength = $maxLength;
    }

    /**
     * Get the message of the last failure. Optional.
     */
    public function getFailureMessage(): string
    {
        if ($this->rejectReason) {
            return 'The JSON-encoded footer is invalid: '.$this->rejectReason;
        }

        return 'The JSON-encoded footer is invalid';
    }

    /**
     * Validate this token according to this rule.
     *
     *
     * @throws EncodingException
     */
    public function isValid(JsonToken $token): bool
    {
        $json = $token->getFooter();
        if (empty($json)) {
            $this->rejectReason = 'Footer is empty, when JSON was expected.';

            return false;
        }
        $length = Binary::safeStrlen($json);
        if ($length > $this->maxLength) {
            $this->rejectReason = "Footer is too long ({$length}, when the maximum allowed is {$this->maxLength})";

            return false;
        }

        $count = Util::countJsonKeys($json);
        if ($count > $this->maxKeys) {
            $this->rejectReason = "Footer has too many keys ({$count}, when the maximum allowed is {$this->maxKeys})";

            return false;
        }

        $depth = Util::calculateJsonDepth($json);
        if ($depth > $this->maxDepth) {
            $this->rejectReason = 'Maximum stack depth exceeded';

            return false;
        }

        /** @var array|bool|null $decoded */
        $decoded = json_decode($json, true, $this->maxDepth);
        /** @psalm-suppress RiskyTruthyFalsyComparison */
        if (! $decoded) {
            $this->rejectReason = json_last_error_msg();
        }

        return is_array($decoded);
    }

    /**
     * Set the maximum permitted depth for the JSON payload in the footer.
     *
     * @param  int<1, 2147483647>  $maxDepth
     */
    public function setMaxDepth(int $maxDepth): self
    {
        $this->maxDepth = $maxDepth;

        return $this;
    }

    /**
     * Set the maximum number of keys in the JSON payload in the footer.
     */
    public function setMaxKeys(int $maxKeys): self
    {
        $this->maxKeys = $maxKeys;

        return $this;
    }

    /**
     * Set the maximum length of the JSON payload in the footer.
     */
    public function setMaxLength(int $maxLength): self
    {
        $this->maxLength = $maxLength;

        return $this;
    }
}
