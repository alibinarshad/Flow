package io.github.aedev.flow

import android.webkit.CookieManager
import okhttp3.Interceptor
import okhttp3.Response
import java.security.MessageDigest

/**
 * Native Grayjay Cookie Bridge for Flow
 * Automatically pulls live session tokens from Android's CookieManager and signs requests.
 */
class GrayjayBridge : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val url = original.url.toString()

        if (!url.contains("youtube.com") && !url.contains("googlevideo.com")) {
            return chain.proceed(original)
        }

        val rawCookies = CookieManager.getInstance().getCookie("https://www.youtube.com") ?: ""
        val sapisid = rawCookies.split(";").map { it.trim() }.firstOrNull { it.startsWith("SAPISID=") }?.substringAfter("=")
            ?: rawCookies.split(";").map { it.trim() }.firstOrNull { it.startsWith("__Secure-3PAPISID=") }?.substringAfter("=")

        val requestBuilder = original.newBuilder()
            .header("Cookie", rawCookies)
            .header("Origin", "https://www.youtube.com")
            .header("Referer", "https://www.youtube.com/")

        if (sapisid != null) {
            val epoch = System.currentTimeMillis() / 1000
            val sha1 = MessageDigest.getInstance("SHA-1")
                .digest("$epoch $sapisid https://www.youtube.com".toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            val hashToken = "${epoch}_$sha1"
            requestBuilder.header("Authorization", "SAPISIDHASH $hashToken")
        }

        return chain.proceed(requestBuilder.build())
    }
}
