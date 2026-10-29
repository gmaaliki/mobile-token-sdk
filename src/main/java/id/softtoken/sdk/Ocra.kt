package id.softtoken.sdk

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest

/** OCRA suite (RFC 6287 section 6). Same parsing rules as soft-token-core (Java). */
data class OcraSuite(
    val value: String,
    val hmacAlgorithm: String,
    val digits: Int,
    val counter: Boolean,
    val questionFormat: Char,
    val pinAlgorithm: String?,
    val sessionLength: Int,
    val timeStepSeconds: Long,
) {
    fun timeStep(epochSecond: Long): Long = Math.floorDiv(epochSecond, timeStepSeconds)

    companion object {
        const val DEFAULT = "OCRA-1:HOTP-SHA256-8:QH64-T1M"
        private val CRYPTO = Regex("HOTP-SHA(1|256|512)-(\\d{1,2})")
        private val QUESTION = Regex("Q([ANH])(\\d{2})")
        private val PIN = Regex("P(SHA1|SHA256|SHA512)")
        private val SESSION = Regex("S(\\d{3})")
        private val TIME = Regex("T(\\d{1,2})([SMH])")

        fun parse(suite: String): OcraSuite {
            val parts = suite.split(":")
            require(parts.size == 3 && parts[0] == "OCRA-1") { "Unsupported OCRA suite: $suite" }
            val crypto = requireNotNull(CRYPTO.matchEntire(parts[1])) { "Bad crypto function" }
            val digits = crypto.groupValues[2].toInt()
            require(digits in 4..10) { "Truncation must be 4..10 digits" }
            var counter = false
            var q: Char? = null
            var pin: String? = null
            var session = 0
            var step = 0L
            for (item in parts[2].split("-")) {
                when {
                    item == "C" -> counter = true
                    QUESTION.matches(item) -> q = item[1]
                    PIN.matches(item) -> pin = item.substring(1)
                    SESSION.matches(item) -> session = item.substring(1).toInt()
                    TIME.matches(item) -> {
                        val m = TIME.matchEntire(item)!!
                        val n = m.groupValues[1].toLong()
                        step = when (m.groupValues[2]) { "S" -> n; "M" -> n * 60; else -> n * 3600 }
                    }
                    else -> throw IllegalArgumentException("Bad data input item: $item")
                }
            }
            return OcraSuite(suite, "HmacSHA" + crypto.groupValues[1], digits, counter,
                requireNotNull(q) { "Suite must contain a question" }, pin, session, step)
        }
    }
}

/** OCRA computation per RFC 6287 section 5. The HMAC is supplied by the caller (Android Keystore Mac in production). */
object Ocra {

    class Input(
        val question: String,
        val timeStep: Long = 0,
        val counter: Long = 0,
        val pinHash: String? = null,
        val session: String? = null,
    )

    fun generate(suite: OcraSuite, input: Input, hmac: (algorithm: String, data: ByteArray) -> ByteArray): String =
        truncate(hmac(suite.hmacAlgorithm, dataInput(suite, input)), suite.digits)

    /** suite | 0x00 | C | Q (128 bytes, right zero-padded) | P | S | T */
    fun dataInput(suite: OcraSuite, input: Input): ByteArray {
        val suiteBytes = suite.value.toByteArray(Charsets.US_ASCII)
        val q = question(suite, input.question)
        val p = if (suite.pinAlgorithm == null) ByteArray(0) else hex(input.pinHash!!)
        val s = if (suite.sessionLength == 0) ByteArray(0) else fixed(hex(input.session!!), suite.sessionLength)
        val buf = ByteBuffer.allocate(suiteBytes.size + 1 + (if (suite.counter) 8 else 0) + q.size + p.size + s.size +
            (if (suite.timeStepSeconds > 0) 8 else 0))
        buf.put(suiteBytes).put(0)
        if (suite.counter) buf.putLong(input.counter)
        buf.put(q).put(p).put(s)
        if (suite.timeStepSeconds > 0) buf.putLong(input.timeStep)
        return buf.array()
    }

    private fun question(suite: OcraSuite, question: String): ByteArray {
        require(question.isNotEmpty()) { "Question is required" }
        val h = when (suite.questionFormat) {
            'N' -> BigInteger(question, 10).toString(16).uppercase()
            'A' -> question.toByteArray(Charsets.US_ASCII).toHex()
            else -> question.also { require(it.matches(Regex("[0-9a-fA-F]+"))) { "Question is not hex" } }
        }
        require(h.length <= 256) { "Question exceeds 128 bytes" }
        return hex(h.padEnd(256, '0'))
    }

    private fun fixed(v: ByteArray, len: Int): ByteArray {
        val out = ByteArray(len)
        System.arraycopy(v, 0, out, maxOf(0, len - v.size), minOf(len, v.size))
        return out
    }

    internal fun truncate(hash: ByteArray, digits: Int): String {
        val o = hash[hash.size - 1].toInt() and 0xf
        val binary = ((hash[o].toInt() and 0x7f) shl 24) or ((hash[o + 1].toInt() and 0xff) shl 16) or
            ((hash[o + 2].toInt() and 0xff) shl 8) or (hash[o + 3].toInt() and 0xff)
        var mod = 1L
        repeat(digits) { mod *= 10 }
        return (binary % mod).toString().padStart(digits, '0')
    }
}

internal fun hex(s: String): ByteArray {
    require(s.length % 2 == 0) { "Odd hex length" }
    return ByteArray(s.length / 2) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

internal fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
