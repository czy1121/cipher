package me.reezy.cosmo.cipher

import android.annotation.SuppressLint
import android.content.Context
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object X509 {
    fun certificate(inputStream: InputStream) = inputStream.use {
        (CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate)
    }

    fun certificate(bytes: ByteArray) = certificate(ByteArrayInputStream(bytes))
    fun certificate(context: Context, filename: String) = certificate(context.assets.open(filename))

    fun sslContext(tm: X509TrustManager): SSLContext {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(tm), null)
        return sslContext
    }

    fun sslSocketFactory(tm: X509TrustManager): SSLSocketFactory {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(tm), null)
        return sslContext.socketFactory
    }


    fun defaultTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val trustManagers = tmf.trustManagers
        check(!(trustManagers.size != 1 || trustManagers[0] !is X509TrustManager)) {
            ("Unexpected default trust managers:" + Arrays.toString(trustManagers))
        }
        return trustManagers[0] as X509TrustManager
    }

    @SuppressLint("CustomX509TrustManager")
    fun trustServer(serverX509Certificate: X509Certificate) = object : X509TrustManager {

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf(serverX509Certificate)

        @SuppressLint("TrustAllX509TrustManager")
        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            // chain.forEach {
            //     logE("checkClientTrusted($authType) => $it")
            // }
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
//        logE("checkServerTrusted($authType) ca => ${ca.issuerDN}")
            chain.forEach { cert ->
//            logE("checkServerTrusted($authType, $index) => ${cert.issuerDN}")
                cert.checkValidity()
                cert.verify(serverX509Certificate.publicKey)
            }
        }
    }


    @SuppressLint("CustomX509TrustManager")
    object TrustAll : X509TrustManager {

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()

        @SuppressLint("TrustAllX509TrustManager")
        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        }

        @SuppressLint("TrustAllX509TrustManager")
        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        }
    }
}
