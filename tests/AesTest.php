<?php

namespace Soli\Tests;

use PHPUnit\Framework\TestCase;
use Soli\Aes;

class AesTest extends TestCase
{
    /**
     * @dataProvider supportedKeySizes
     */
    public function testOpensslAes($keySize)
    {
        $data = "hello world.";
        $secret = "your_secret";

        $aes = new Aes($keySize);
        $encrypted = $aes->encrypt($data, $secret);
        $decrypted = $aes->decrypt($encrypted, $secret);

        $this->assertEquals($data, $decrypted);
    }

    public function supportedKeySizes()
    {
        return [
            [128],
            [192],
            [256],
        ];
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessageRegExp /The cipher "KeySize" requested is not supported by AES.+/
     */
    public function testOpensslAesNotSupportedKeySize()
    {
        $supportedKeySizes = array_column($this->supportedKeySizes(), "0");

        do {
            $notSupportedKeySize = rand(1, 1000);
        } while (in_array($notSupportedKeySize, $supportedKeySizes));

        new Aes($notSupportedKeySize);
    }

    /**
     * @dataProvider supportedKeySizes
     */
    public function testGetOpenSslName($keySize)
    {
        $this->assertEquals("aes-{$keySize}-cbc", (new Aes($keySize))->getOpenSslName());
    }

    public function testGetAesName()
    {
        $this->assertEquals("AES/CBC/PKCS5Padding", (new Aes())->getAesName());
    }

    public function testRequiresPadding()
    {
        $this->assertEquals(true, (new Aes())->requiresPadding());
    }
}
