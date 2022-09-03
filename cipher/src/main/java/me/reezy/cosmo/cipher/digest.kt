package me.reezy.cosmo.cipher

import java.security.MessageDigest


/****** digest *******/

/** 128-bit MD5 */
fun ByteArray.md5(): ByteArray = digest("md5")

/** 160-bit SHA-1 */
fun ByteArray.sha1(): ByteArray = digest("SHA-1")
fun ByteArray.sha256(): ByteArray = digest("SHA-256")
fun ByteArray.sha512(): ByteArray = digest("SHA-512")


private fun ByteArray.digest(algorithm: String): ByteArray = MessageDigest.getInstance(algorithm).digest(this)

