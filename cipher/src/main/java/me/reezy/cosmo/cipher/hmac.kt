package me.reezy.cosmo.cipher

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


/****** hmac *******/

fun ByteArray.hmacSha1(key: ByteArray): ByteArray = hmac(key, "HmacSHA1")
fun ByteArray.hmacSha256(key: ByteArray): ByteArray = hmac(key, "HmacSHA256")
fun ByteArray.hmacSha512(key: ByteArray): ByteArray = hmac(key, "HmacSHA512")

private fun ByteArray.hmac(key: ByteArray, algorithm: String): ByteArray {
    val mac = Mac.getInstance(algorithm)
    mac.init(SecretKeySpec(key, algorithm))
    return mac.doFinal(this)
}