<?php

namespace ParagonIE\Paseto\Tests;

use ParagonIE\Paseto\Encoder\Hex;
use PHPUnit\Framework\TestCase;
class HexTest extends TestCase
{
    /**
     * @covers Hex::encode()
     * @covers Hex::decode()
     * @covers Hex::encodeUpper()
     */
    public function testRandom()
    {
        for ($i = 1; $i < 32; ++$i) {
            for ($j = 0; $j < 50; ++$j) {
                $random = \random_bytes($i);

                $enc = Hex::encode($random);
                $this->assertSame(
                    $random,
                    Hex::decode($enc)
                );
                $this->assertSame(
                    \bin2hex($random),
                    $enc
                );
            }
        }
    }
}
