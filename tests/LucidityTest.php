<?php
declare(strict_types=1);
namespace ParagonIE\Paseto\Tests;

use Exception;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Contracts\KeyInterface;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version4;
use PHPUnit\Framework\TestCase;
use TypeError;

class LucidityTest extends TestCase
{
    /**
     * @return array[]
     * @throws Exception
     */
    public static function luciditySymmetric(): array
    {
        $v4_lk = Version4::generateSymmetricKey();
        $v4_sk = Version4::generateAsymmetricSecretKey();
        $v4_pk = $v4_sk->getPublicKey();

        return [
            [
                new Version4,
                $v4_lk,
                $v4_pk
            ], [
                new Version4,
                $v4_lk,
                $v4_sk
            ],
        ];
    }

    /**
     * @param Version4 $protocol
     * @param KeyInterface $validKey
     * @param KeyInterface $invalidKey
     *
     * @dataProvider luciditySymmetric
     * @throws Exception
     * @throws PasetoException
     */
    public function testLocalLucidity(
        $protocol,
        KeyInterface $validKey,
        KeyInterface $invalidKey
    ) {
        $dummy = '{"test":true}';
        $encode = $protocol::encrypt($dummy, $validKey);
        $decode = $protocol::decrypt($encode, $validKey);
        $this->assertSame($decode, $dummy);

        $this->expectException(PasetoException::class);
        try {
            $protocol::decrypt($encode, $invalidKey);
        } catch (TypeError $ex) {
            throw new PasetoException('TypeError', 0, $ex);
        }
    }
}
