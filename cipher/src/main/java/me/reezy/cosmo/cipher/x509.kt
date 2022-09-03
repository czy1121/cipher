package me.reezy.cosmo.cipher


import android.annotation.SuppressLint
import android.content.Context
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.*



fun Context.loadX509Certificate(filename: String) = assets.open(filename).use {
    (CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate)
}

fun X509TrustManager.createSSLContext(): SSLContext {
    val sslContext = SSLContext.getInstance("TLSv1", "AndroidOpenSSL")
    sslContext.init(null, arrayOf(this), null)
    return sslContext
}

@SuppressLint("CustomX509TrustManager")
class CustomX509TrustManager(private val ca: X509Certificate) : X509TrustManager {

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf(ca)

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
            cert.verify(ca.publicKey)
        }
    }
}