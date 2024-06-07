<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Encoder\Binary;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Exception\SecurityException;
use ParagonIE\Paseto\Keys\Base\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Base\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\Util;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    public static function pemProvider(): array
    {
        return [
            [
                AsymmetricSecretKey::fromEncodedString(
                    't6Rbm0ASlC9TnLprftH5iSVq0yo1_7QEdPMiUXbiGFbD2VZn-_XpTgHTuMrH3oiu2eDNo9vVRgvh39Exl5RBGg',
                    new Version4
                ),

                "-----BEGIN EC PRIVATE KEY-----\n".
                "MC4CAQAwBQYDK2VwBCIEILekW5tAEpQvU5y6a37R+YklatMqNf+0BHTzIlF24hhW\n".
                "w9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n".
                '-----END EC PRIVATE KEY-----',

                "-----BEGIN PUBLIC KEY-----\n".
                "MCowBQYDK2VwAyEAw9lWZ/v16U4B07jKx96IrtngzaPb1UYL4d/RMZeUQRo=\n".
                '-----END PUBLIC KEY-----',
            ],
        ];
    }

    /**
     * @dataProvider pemProvider
     */
    public function testExportImportPem(AsymmetricSecretKey $sk, string $skPem, string $pkPem): void
    {
        $this->assertSame($skPem, $sk->encodePem());
        $pk = $sk->getPublicKey();
        $this->assertSame(
            Util::dos2unix($pk->encodePem()),
            Util::dos2unix($pkPem)
        );

        $this->assertSame(
            $sk->raw(),
            AsymmetricSecretKey::importPem($sk->encodePem(), $sk->getProtocol())->raw(),
        );
        $this->assertSame(
            $pk->raw(),
            AsymmetricPublicKey::importPem($pk->encodePem(), $pk->getProtocol())->raw(),
        );
    }

    public function testInvalidEdDSAKey()
    {
        if (! extension_loaded('sodium')) {
            $this->markTestSkipped('Slow test on sodium_compat');
        }
        $keypair1 = sodium_crypto_sign_keypair();
        $keypair2 = sodium_crypto_sign_keypair();

        $good1 = Binary::safeSubstr($keypair1, 0, 64);
        $good2 = Binary::safeSubstr($keypair2, 0, 64);
        $bad = Binary::safeSubstr($keypair1, 0, 32).Binary::safeSubstr($keypair2, 32, 32);

        (AsymmetricSecretKey::newVersionKey($good1, new Version4()))->assertSecretKeyValid();
        (AsymmetricSecretKey::newVersionKey($good2, new Version4()))->assertSecretKeyValid();

        $this->expectException(SecurityException::class);
        (AsymmetricSecretKey::newVersionKey($bad, new Version4()))->assertSecretKeyValid();
    }

    public function testShortV4SymmetricKey()
    {
        $this->expectException(PasetoException::class);
        new SymmetricKey(random_bytes(31), new Version4());
    }

    public function testLongV4SymmetricKey()
    {
        $this->expectException(PasetoException::class);
        new SymmetricKey(random_bytes(33), new Version4());
    }
}
