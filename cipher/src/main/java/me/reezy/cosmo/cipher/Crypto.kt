package me.reezy.cosmo.cipher

import java.lang.Exception
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


object Crypto {
    const val RSA = "RSA"
    const val AES = "AES"
    const val AES_CBC_PKCS7 = "AES/CBC/PKCS7Padding"
    const val AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding"
    const val AES_CBC_NO_PADDING = "AES/CBC/NoPadding"

    private val random = try {
        SecureRandom.getInstance("SHA1PRNG")
    } catch (e: Exception) {
        SecureRandom()
    }

    /** 加密 */
    fun encrypt(input: ByteArray, key: ByteArray, alg: String): ByteArray {
        val secretKey = SecretKeySpec(key, alg)
        val cipher = Cipher.getInstance(alg)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(input)
    }

    /** 解密 */
    fun decrypt(input: ByteArray, key: ByteArray, alg: String): ByteArray {
        val secretKey = SecretKeySpec(key, alg)
        val cipher = Cipher.getInstance(alg)
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return cipher.doFinal(input)
    }

    /** 加密 */
    fun encrypt(input: ByteArray, key: ByteArray, iv: ByteArray, alg: String, transformation: String): ByteArray {
        val secretKey = SecretKeySpec(key, alg)
        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        return cipher.doFinal(input)
    }

    /** 解密 */
    fun decrypt(input: ByteArray, key: ByteArray, iv: ByteArray, alg: String, transformation: String): ByteArray {
        val secretKey = SecretKeySpec(key, alg)
        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        return cipher.doFinal(input)
    }




    /** rsa 加密/解密 */
    fun rsa(data: ByteArray, opmode: Int, key: Key): ByteArray {
        val cipher = Cipher.getInstance(RSA)
        cipher.init(opmode, key)
        return cipher.doFinal(data)
    }

    fun rsaPublicKey(key: ByteArray): PublicKey = KeyFactory.getInstance(RSA).generatePublic(X509EncodedKeySpec(key))
    fun rsaPrivateKey(key: ByteArray): PrivateKey = KeyFactory.getInstance(RSA).generatePrivate(PKCS8EncodedKeySpec(key))
    fun aesKey(keysize: Int = 128):ByteArray = generateKey(AES, keysize).encoded

    fun generateKey(alg: String, keysize: Int): Key {
        val keyGenerator = KeyGenerator.getInstance(alg)
        keyGenerator.init(keysize)
        return keyGenerator.generateKey()
    }

    fun generateIV(size: Int = 16): ByteArray {
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }
}