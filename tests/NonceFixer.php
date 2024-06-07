<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Contracts\ProtocolInterface;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;

abstract class NonceFixer {
    public static function buildUnitTestEncrypt(ProtocolInterface $protocol): \Closure {
        return static function (
            string $data,
            SymmetricKey $key,
            string $footer = '',
            string $implicit = '',
            string $nonceForUnitTesting = ''
        ) use ($protocol): string {
            // invoke protected $protocol::__encrypt method via reflection
            $reflection = new \ReflectionClass(get_class($protocol));
            $method = $reflection->getMethod('__encrypt');
            return $method->invokeArgs($protocol, [$data, $key, $footer, $implicit, $nonceForUnitTesting]);
        };
    }

    public static function buildSetExplicitNonce(): \Closure {
        return function (string $nonce) {
            /** @noinspection Annotator */
            $this->unitTestEncrypter = static function (ProtocolInterface $protocol) use ($nonce) {
                $class = new class {
                    private static $nonce;
                    private static $protocol;

                    public static function setNonce(string $nonce)
                    {
                        self::$nonce = $nonce;
                    }

                    public static function setProtocol(ProtocolInterface $protocol)
                    {
                        self::$protocol = $protocol;
                    }

                    public static function encrypt(
                        string $data,
                        SymmetricKey $key,
                        string $footer = '',
                        string $implicit = ''
                    ): string {
                        return NonceFixer::buildUnitTestEncrypt(self::$protocol)->bindTo(null, self::$protocol)(
                            $data,
                            $key,
                            $footer,
                            $implicit,
                            self::$nonce
                        );
                    }
                };

                $class::setNonce($nonce);
                $class::setProtocol($protocol);

                return $class;
            };
        };
    }
}
