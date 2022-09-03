@file:Suppress("NOTHING_TO_INLINE")
package me.reezy.cosmo.cipher

import javax.crypto.Cipher


/****** rsa *******/

inline fun ByteArray.rsaEncrypt(publicKey: ByteArray): ByteArray = Crypto.rsa(this, Cipher.ENCRYPT_MODE, Crypto.rsaPublicKey(publicKey))
inline fun ByteArray.rsaDecrypt(publicKey: ByteArray): ByteArray = Crypto.rsa(this, Cipher.DECRYPT_MODE, Crypto.rsaPublicKey(publicKey))

inline fun String.rsaEncrypt(publicKey: String): String = String(Crypto.rsa(this.toByteArray(), Cipher.ENCRYPT_MODE, Crypto.rsaPublicKey(publicKey.toByteArray())))
inline fun String.rsaDecrypt(publicKey: String): String = String(Crypto.rsa(this.toByteArray(), Cipher.DECRYPT_MODE, Crypto.rsaPublicKey(publicKey.toByteArray())))