<?php

declare(strict_types=1);

namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Contracts\ReceivingKey;
use ParagonIE\Paseto\Contracts\SendingKey;
use ParagonIE\Paseto\Exception\InvalidPurposeException;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey as V4AsymmetricSecretKey;
use ParagonIE\Paseto\Purpose;
use PHPUnit\Framework\TestCase;

class PurposeTest extends TestCase
{
    public static function receivingKeyProvider(): array
    {
        $bk = SymmetricKey::generate();
        $sk4 = V4AsymmetricSecretKey::generate();
        $pk4 = $sk4->getPublicKey();

        return [
            [$bk, 'local'],
            [$pk4, 'public'],
        ];
    }

    public static function sendingKeyProvider(): array
    {
        $bk = SymmetricKey::generate();
        $sk4 = V4AsymmetricSecretKey::generate();

        return [
            [$bk, 'local'],
            [$sk4, 'public'],
        ];
    }

    /**
     * @dataProvider receivingKeyProvider
     *
     * @throws InvalidPurposeException
     */
    public function testReceivingMapping(ReceivingKey $key, string $expected): void
    {
        $purpose = Purpose::fromReceivingKey($key);
        $this->assertSame($expected, $purpose->rawString());
    }

    /**
     * @dataProvider sendingKeyProvider
     *
     * @throws InvalidPurposeException
     */
    public function testSendingMapping(SendingKey $key, string $expected): void
    {
        $purpose = Purpose::fromSendingKey($key);
        $this->assertSame($expected, $purpose->rawString());
    }
}
