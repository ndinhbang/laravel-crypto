<?php

declare(strict_types=1);

namespace ParagonIE\Paseto;

use LogicException;
use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Exception\ExceptionCode;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Protocol\Version4;
use TypeError;

use function array_key_exists;
use function array_map;
use function get_class;
use function in_array;

final class ProtocolCollection
{
    /**
     * Our built-in allow-list of protocol types is defined here.
     *
     * @const array<int, class-string<ProtocolInterface>>
     *
     * @var array<int, class-string<ProtocolInterface>>
     */
    const ALLOWED = [
        Version4::class,
    ];

    /** @var array<array-key, ProtocolInterface> */
    private array $protocols;

    /** @var array<string, ProtocolInterface> */
    private static array $headerLookup = [];

    /**
     * @throws LogicException
     * @throws InvalidVersionException
     */
    public function __construct(ProtocolInterface ...$protocols)
    {
        if (empty($protocols)) {
            throw new LogicException(
                'At least one version is necessary',
                ExceptionCode::BAD_VERSION
            );
        }

        foreach ($protocols as $protocol) {
            self::throwIfUnsupported($protocol);
        }

        $this->protocols = $protocols;
    }

    /**
     * Does the collection contain the given protocol
     */
    public function has(ProtocolInterface $protocol): bool
    {
        return in_array($protocol, $this->protocols);
    }

    /**
     * Is the given protocol supported?
     */
    public static function isValid(ProtocolInterface $protocol): bool
    {
        return in_array(get_class($protocol), self::ALLOWED, true);
    }

    /**
     * Throws if the given protocol is unsupported
     *
     * @throws InvalidVersionException
     */
    public static function throwIfUnsupported(ProtocolInterface $protocol): void
    {
        if (! self::isValid($protocol)) {
            throw new InvalidVersionException(
                'Unsupported version: '.$protocol::header(),
                ExceptionCode::BAD_VERSION
            );
        }
    }

    /**
     * Return the PASETO protocol version for a given header snippet
     *
     * @throws InvalidVersionException
     */
    public static function protocolFromHeaderPart(string $headerPart): ProtocolInterface
    {
        if (empty(self::$headerLookup)) {
            foreach (self::ALLOWED as $protocolClass) {
                if (! method_exists($protocolClass, 'header')) {
                    throw new TypeError(
                        "Object {$protocolClass} does not have a header() method",
                        ExceptionCode::IMPOSSIBLE_CONDITION
                    );
                }
                self::$headerLookup[$protocolClass::header()] = new $protocolClass;
            }
        }

        if (! array_key_exists($headerPart, self::$headerLookup)) {
            throw new InvalidVersionException(
                'Disallowed or unsupported version',
                ExceptionCode::BAD_VERSION
            );
        }

        return self::$headerLookup[$headerPart];
    }

    /**
     * Get a collection of all supported protocols
     *
     * @throws InvalidVersionException
     */
    public static function default(): self
    {
        return new self(...array_map(
            function (string $p): ProtocolInterface {
                return new $p;
            },
            self::ALLOWED
        ));
    }

    /**
     * Get a collection containing protocol version 4.
     *
     * @throws InvalidVersionException
     */
    public static function v4(): self
    {
        return new self(new Version4);
    }
}
