<?php

declare(strict_types=1);

namespace ParagonIE\Paseto;

use ParagonIE\Paseto\Contracts\ReceivingKey;
use ParagonIE\Paseto\Contracts\SendingKey;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\InvalidPurposeException;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey as LegacyAsymmetricPublicKey;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey as LegacyAsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Keys\SymmetricKey as LegacySymmetricKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey as V4AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey as V4AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey as V4SymmetricKey;

use function get_class;
use function hash_equals;
use function in_array;

final class Purpose
{
    /**
     * An allow-list of allowed values/modes. This simulates an enum.
     *
     * @const array<int, string>
     */
    const ALLOWLIST = [
        'local',
        'public',
    ];

    /**
     * When sending, which type of key is expected for each mode.
     *
     * @const array<string, string>
     */
    const EXPECTED_SENDING_KEYS = [
        'local' => SymmetricKey::class,
        'public' => AsymmetricSecretKey::class,
    ];

    /**
     * Maps the fully-qualified class names for various SendingKey
     * objects to the expected purpose string.
     *
     * @const array<string, string>
     */
    const SENDING_KEY_MAP = [
        LegacySymmetricKey::class => 'local',
        SymmetricKey::class => 'local',
        V4SymmetricKey::class => 'local',
        AsymmetricSecretKey::class => 'public',
        LegacyAsymmetricSecretKey::class => 'public',
        V4AsymmetricSecretKey::class => 'public',
    ];

    /**
     * When receiving, which type of key is expected for each mode.
     *
     * @const array<string, string>
     */
    const EXPECTED_RECEIVING_KEYS = [
        'local' => SymmetricKey::class,
        'public' => AsymmetricPublicKey::class,
    ];

    /**
     * Maps the fully-qualified class names for various ReceivingKey
     * objects to the expected purpose string.
     *
     * @const array<string, string>
     */
    const RECEIVING_KEY_MAP = [
        LegacySymmetricKey::class => 'local',
        SymmetricKey::class => 'local',
        V4SymmetricKey::class => 'local',
        AsymmetricPublicKey::class => 'public',
        LegacyAsymmetricPublicKey::class => 'public',
        V4AsymmetricPublicKey::class => 'public',
    ];

    /**
     * Inverse of EXPECTED_SENDING_KEYS, evaluated and statically cached at runtime.
     *
     * @var array<string, string>
     */
    private static array $sendingKeyToPurpose = [];

    /**
     * Inverse of EXPECTED_RECEIVING_KEYS, evaluated and statically cached at runtime.
     *
     * @var array<string, string>
     */
    private static array $receivingKeyToPurpose = [];

    private string $purpose;

    /**
     * Allowed values in self::ALLOWLIST
     *
     * @throws InvalidPurposeException
     */
    public function __construct(string $rawString)
    {
        if (! self::isValid($rawString)) {
            throw new InvalidPurposeException(
                'Unknown purpose: '.$rawString,
                ExceptionCode::PURPOSE_NOT_LOCAL_OR_PUBLIC
            );
        }

        $this->purpose = $rawString;
    }

    /**
     * Create a local purpose.
     */
    public static function local(): self
    {
        return new self('local');
    }

    /**
     * Create a public purpose.
     */
    public static function public(): self
    {
        return new self('public');
    }

    /**
     * Given a SendingKey, retrieve the corresponding Purpose.
     *
     * @throws InvalidPurposeException
     */
    public static function fromSendingKey(#[\SensitiveParameter] SendingKey $key): self
    {
        if (empty(self::$sendingKeyToPurpose)) {
            self::$sendingKeyToPurpose = self::SENDING_KEY_MAP;
        }
        $keyClass = get_class($key);
        if (! array_key_exists($keyClass, self::$sendingKeyToPurpose)) {
            throw new InvalidPurposeException('Unknown key class:'.$keyClass);
        }

        return new self(self::$sendingKeyToPurpose[$keyClass]);
    }

    /**
     * Given a ReceivingKey, retrieve the corresponding Purpose.
     *
     * @throws InvalidPurposeException
     */
    public static function fromReceivingKey(#[\SensitiveParameter] ReceivingKey $key): self
    {
        if (empty(self::$receivingKeyToPurpose)) {
            self::$receivingKeyToPurpose = self::RECEIVING_KEY_MAP;
        }
        $keyClass = get_class($key);
        if (! array_key_exists($keyClass, self::$receivingKeyToPurpose)) {
            throw new InvalidPurposeException('Unknown key class:'.$keyClass);
        }

        return new self(self::$receivingKeyToPurpose[get_class($key)]);
    }

    /**
     * Compare the instance with $purpose in constant time.
     */
    public function equals(self $purpose): bool
    {
        return hash_equals($purpose->purpose, $this->purpose);
    }

    /**
     * Determine whether new Purpose($rawString) will succeed prior to calling it.
     */
    public static function isValid(string $rawString): bool
    {
        return in_array($rawString, self::ALLOWLIST, true);
    }

    /**
     * Does the given $key correspond to the expected SendingKey for the
     * instance's mode?
     */
    public function isSendingKeyValid(#[\SensitiveParameter] SendingKey $key): bool
    {
        $expectedKeyType = $this->expectedSendingKeyType();

        return $key instanceof $expectedKeyType;
    }

    /**
     * Does the given $key correspond to the expected ReceivingKey for the instance's mode?
     */
    public function isReceivingKeyValid(#[\SensitiveParameter] ReceivingKey $key): bool
    {
        $expectedKeyType = $this->expectedReceivingKeyType();

        return $key instanceof $expectedKeyType;
    }

    /**
     * Retrieve the class name as a string which corresponds to the expected
     * SendingKey for the instance's mode.
     */
    public function expectedSendingKeyType(): string
    {
        return self::EXPECTED_SENDING_KEYS[$this->rawString()];
    }

    /**
     * Retrieve the class name as a string which corresponds to the expected
     * ReceivingKey for the instance's mode.
     */
    public function expectedReceivingKeyType(): string
    {
        return self::EXPECTED_RECEIVING_KEYS[$this->rawString()];
    }

    /**
     * Retrieve the underlying raw string value for the instance's mode.
     */
    public function rawString(): string
    {
        return $this->purpose;
    }
}
