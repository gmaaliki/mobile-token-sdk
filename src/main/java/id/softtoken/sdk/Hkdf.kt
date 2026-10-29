package id.softtoken.sdk

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 5869 HKDF-SHA256, identical to soft-token-core EnrollmentCrypto.hkdfSha256. */
object Hkdf {
    fun sha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        prk.fill(0)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        t.fill(0)
        return out
    }

    fun seedInfo(tokenId: String): ByteArray = "ocra-seed|$tokenId".toByteArray(Charsets.UTF_8)
}
