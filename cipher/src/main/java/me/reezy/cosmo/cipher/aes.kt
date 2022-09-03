@file:Suppress("NOTHING_TO_INLINE")

package me.reezy.cosmo.cipher

/****** aes *******/

/** 加密 */
inline fun ByteArray.aesEncrypt(key: ByteArray): ByteArray = Crypto.encrypt(this, key, Crypto.AES)

/** 加密 */
inline fun ByteArray.aesEncrypt(key: ByteArray, iv: ByteArray): ByteArray = Crypto.encrypt(this, key, iv, Crypto.AES, Crypto.AES_CBC_PKCS7)

/** 解密 */
inline fun ByteArray.aesDecrypt(key: ByteArray): ByteArray = Crypto.decrypt(this, key, Crypto.AES)

/** 解密 */
inline fun ByteArray.aesDecrypt(key: ByteArray, iv: ByteArray): ByteArray = Crypto.decrypt(this, key, iv, Crypto.AES, Crypto.AES_CBC_PKCS7)
