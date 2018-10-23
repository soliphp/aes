<?php
/**
 * @author ueaner <ueaner@gmail.com>
 */
namespace Soli;

/**
 * 基于 openssl 扩展的 AES 加解密
 *
 * 支持 AES-256-CBC, AES-192-CBC, AES-128-CBC
 * 兼容 openssl 命令行
 */
class Aes
{
    private $messageDigest = 'md5';

    private $keySize;

    private $supportedKeySizes = [128, 192, 256];

    public function __construct($keySize = 256)
    {
        $this->setKeySize($keySize);
    }

    public function setKeySize($keySize)
    {
        if (!in_array($keySize, $this->supportedKeySizes)) {
            throw new \InvalidArgumentException('The cipher "KeySize" requested'
                . ' is not supported by AES (128, 192, or 256).');
        }

        $this->keySize = $keySize;
    }

    /**
     * Encrypt the string data, using the password secret.
     *
     * echo -n <data> | openssl aes-256-cbc -md md5 -base64 -pass pass:<secret>
     *
     * @param string $data
     * @param string $secret
     * @return string
     */
    public function encrypt($data, $secret)
    {
        // salt: 8 byte
        $salt = openssl_random_pseudo_bytes(8);

        list($key, $iv) = $this->deriveKeyAndIV($secret, $salt);

        $method = $this->getOpenSslName();
        $options = OPENSSL_RAW_DATA;

        $encrypted =  openssl_encrypt($data, $method, $key, $options, $iv);

        return base64_encode('Salted__' . $salt . $encrypted);
    }

    /**
     * Decrypt the string data, using the password secret.
     *
     * echo <data> | openssl aes-256-cbc -md md5 -d -base64 -pass pass:<secret>
     *
     * @param string $data
     * @param string $secret
     * @return string
     */
    public function decrypt($data, $secret)
    {
        $decoded = base64_decode($data);
        // salt: 8 ~ 16 byte
        $salt = substr($decoded, 8, 8);
        // data: 16 ~ end byte
        $encrypted = substr($decoded, 16);

        list($key, $iv) = $this->deriveKeyAndIV($secret, $salt);

        $method = $this->getOpenSslName();
        $options = OPENSSL_RAW_DATA;

        return openssl_decrypt($encrypted, $method, $key, $options, $iv);
    }

    /**
     * Derive an key and IV from a password and a salt
     *
     * @param string $password
     * @param string $salt
     * @return array [$key, $iv]
     */
    protected function deriveKeyAndIV($password, $salt)
    {
        $hash1 = md5($password . $salt, true);

        $hash2 = md5($hash1 . $password . $salt, true);

        $hash3 = md5($hash2 . $password . $salt, true);

        return [
            $hash1 . $hash2, // key: 0 ~ 32 byte
            $hash3           // iv: 32 ~ 48 byte
        ];
    }

    public function getOpenSslName()
    {
        return "aes-{$this->keySize}-cbc";
    }

    public function getAesName()
    {
        return 'AES/CBC/PKCS5Padding';
    }

    public function requiresPadding()
    {
        return true;
    }
}
