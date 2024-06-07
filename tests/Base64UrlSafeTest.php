<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Encoder\Base64UrlSafe;
use ParagonIE\Paseto\Encoder\Binary;
use PHPUnit\Framework\TestCase;
use SodiumException;

class Base64UrlSafeTest extends TestCase
{
    /**
     * @covers Base64UrlSafe::encode()
     * @covers Base64UrlSafe::decode()
     */
    public function testRandom()
    {
        for ($i = 1; $i < 32; ++$i) {
            for ($j = 0; $j < 50; ++$j) {
                $random = \random_bytes($i);

                $enc = Base64UrlSafe::encode($random);
                $this->assertSame(
                    $random,
                    Base64UrlSafe::decode($enc)
                );
                $this->assertSame(
                    \strtr(\base64_encode($random), '+/', '-_'),
                    $enc
                );

                $unpadded = \rtrim($enc, '=');
                $this->assertSame(
                    $unpadded,
                    Base64UrlSafe::encodeNoPadding($random)
                );

                $this->assertSame(
                    $random,
                    Base64UrlSafe::decode($unpadded, true)
                );
                $this->expectException(SodiumException::class);
                $this->assertSame(
                    $random,
                    Base64UrlSafe::decode($unpadded)
                );
            }
        }

        $random = \random_bytes(1 << 20);
        $enc = Base64UrlSafe::encode($random);
        $this->assertTrue(Binary::safeStrlen($enc) > 65536);
        $this->assertSame(
            $random,
            Base64UrlSafe::decode($enc)
        );
        $this->assertSame(
            \strtr(\base64_encode($random), '+/', '-_'),
            $enc
        );
    }

    public function testDecodeNoPadding()
    {
        Base64UrlSafe::decodeNoPadding('000');
        $this->expectException(SodiumException::class);
        Base64UrlSafe::decodeNoPadding('000=');
    }
}
