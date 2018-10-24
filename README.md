Soli OpenSSL Aes
----------------

基于 OpenSSL 扩展的 AES 加解密库。

* 支持 AES-256-CBC, AES-192-CBC, AES-128-CBC
* 兼容 LibreSSL 2.2+ 命令行
* 兼容 OpenSSL 1.0+ 命令行
* 查看 OpenSSL 版本 `openssl version`

[![Build Status](https://travis-ci.org/soliphp/aes.svg?branch=master)](https://travis-ci.org/soliphp/aes)
[![Coverage Status](https://coveralls.io/repos/github/soliphp/aes/badge.svg?branch=master)](https://coveralls.io/github/soliphp/aes?branch=master)
[![License](https://poser.pugx.org/soliphp/aes/license)](https://packagist.org/packages/soliphp/aes)


## 安装

使用 `composer` 进行安装：

    composer require soliphp/aes

## 使用

    include __DIR__ . '/vendor/autoload.php';

    $aes = new \Soli\Aes();

    $data = 'hello world.';
    $secret = 'your_secret';

    $encrypted = $aes->encrypt($data, $secret);

    $decrypted = $aes->decrypt($encrypted, $secret);

    var_dump($decrypted);

## 加密数据

    $aes = new \Soli\Aes();

    $encrypted = $aes->encrypt('hello world.', 'your_secret');

## 解密数据

    $aes = new \Soli\Aes();

    $decrypted = $aes->decrypt('U2FsdGVkX1/mgtCqMAn6S9AKVrqjPn8NoJkysV5JPII=', 'your_secret');

## 256/192/128

默认使用 AES-256-CBC

    $aes = new \Soli\Aes();
    // 等同于
    $aes = new \Soli\Aes(256);

使用 AES-192-CBC

    $aes = new \Soli\Aes(192);

使用 AES-128-CBC

    $aes = new \Soli\Aes(128);

## 使用 OpenSSL 命令行加解密

加密数据：

    $ echo -n 'hello world.' | openssl aes-256-cbc -md md5 -base64 -pass pass:your_secret
    U2FsdGVkX1/mgtCqMAn6S9AKVrqjPn8NoJkysV5JPII=

解密数据：

    $ echo 'U2FsdGVkX1/mgtCqMAn6S9AKVrqjPn8NoJkysV5JPII=' | openssl aes-256-cbc -md md5 -d -base64 -pass pass:your_secret

注：如果命令行下加密的数据含有特殊字符，导致无法加密，使用`单引号`包裹，如：

    $ echo -n 'hello ~!@%^&*()\{}[]/?' | openssl aes-256-cbc -md md5 -base64 -pass pass:'~!@%^&*()\{}[]/?'

## md5/sha256 信息摘要算法

摘自 [OpenSSL sha256 HISTORY](https://www.openssl.org/docs/man1.1.0/apps/sha256.html#HISTORY)

    The default digest was changed from MD5 to SHA256 in OpenSSL 1.1.0 The FIPS-related options were removed in OpenSSL 1.1.0
    在 OpenSSL 1.1.0 版本中，默认信息摘要算法从 MD5 更改为 SHA256

所以在使用 OpenSSL 命令行加解密数据时务必显示指定 `-md md5` 参数，
以便在 OpenSSL 1.0 和 1.1 版本下执行命令时都可成功加解密。

当前项目目前只支持 md5 方式。

## 参考

    https://github.com/chmduquesne/minibackup/blob/master/samples/OpensslAES.java

## 测试

    $ cd /path/to/soliphp/aes/
    $ composer install
    $ phpunit


## MIT License

MIT Public License
