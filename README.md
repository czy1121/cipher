# cipher

工具类：digest/encoding/hmac/rsa/aes

主要功能

- 摘要(digest)：md5/sha1/sha256/sha512
- 编码(encoding)：hex/decodeHex
- 消息认证码(hash-based message authentication code)：hmacSha1/hmacSha256/hmacSha512
- 加解密(encryption/decryption)：aesEncrypt/aesDecrypt, rsaEncrypt/rsaDecrypt


## Gradle

``` groovy
repositories {
    maven { url "https://gitee.com/ezy/repo/raw/cosmo/"}
}
dependencies {
    implementation "me.reezy.cosmo:cipher:0.8.0"
}
```

## LICENSE

The Component is open-sourced software licensed under the [Apache license](LICENSE).