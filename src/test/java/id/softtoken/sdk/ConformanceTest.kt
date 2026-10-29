package id.softtoken.sdk

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Same vectors as soft-token-core: ../conformance/ocra-vectors.json. */
class ConformanceTest {

    private val vectors = Json.parseToJsonElement(File("../conformance/ocra-vectors.json").readText()).jsonObject
    private val project = vectors["project"]!!.jsonObject

    private fun JsonObject.s(k: String) = this[k]?.jsonPrimitive?.content

    private fun compute(v: JsonObject): String {
        val suite = OcraSuite.parse(v.s("suite")!!)
        val step = v.s("timeStepHex")?.toLong(16) ?: v.s("timeStep")?.toLong() ?: 0
        val input = Ocra.Input(v.s("question")!!, step, v.s("counter")?.toLong() ?: 0, v.s("pinHash"))
        return Ocra.generate(suite, input) { alg, data ->
            Mac.getInstance(alg).apply { init(SecretKeySpec(hex(v.s("key")!!), alg)) }.doFinal(data)
        }
    }

    @Test
    fun rfc6287AppendixC() {
        val rfc = vectors["rfc6287"]!!.jsonArray
        assertEquals(70, rfc.size)
        rfc.forEach { assertEquals(it.toString(), it.jsonObject.s("expected"), compute(it.jsonObject)) }
    }

    @Test
    fun projectOcraVectors() {
        val ocra = project["ocra"]!!.jsonArray
        assertTrue(ocra.isNotEmpty())
        ocra.forEach { assertEquals(it.jsonObject.s("expected"), compute(it.jsonObject)) }
    }

    @Test
    fun canonicalFormAndChallenge() {
        project["transactions"]!!.jsonArray.forEach {
            val tx = it.jsonObject["tx"]!!.jsonObject
            val t = Transaction(tx.s("txId")!!, tx.s("amount")!!, tx.s("currency")!!, tx.s("creditorAccount")!!,
                tx.s("creditorName")!!, tx.s("timestamp")!!)
            assertEquals(it.jsonObject.s("canonical"), t.canonical())
            assertEquals(it.jsonObject.s("challenge"), t.challenge())
        }
    }

    @Test
    fun qrPayloadsParse() {
        project["qrPayloads"]!!.jsonArray.forEach {
            val encoded = it.jsonObject.s("encoded")!!
            val decoded = Json.parseToJsonElement(it.jsonObject.s("json")!!).jsonObject
            val req = QrPayloads.parse(encoded, decoded["iat"]!!.jsonPrimitive.long)
            assertEquals(decoded.s("cid"), req.challengeId)
            assertEquals(decoded.s("ch"), req.challenge)
        }
    }

    @Test
    fun hkdf() {
        project["hkdf"]!!.jsonArray.forEach {
            val v = it.jsonObject
            val okm = Hkdf.sha256(hex(v.s("salt")!!), hex(v.s("ikm")!!), v.s("info")!!.toByteArray(), v["length"]!!.jsonPrimitive.int)
            assertEquals(v.s("okm"), okm.toHex())
        }
    }

    @Test
    fun qrRejections() {
        val v = project["qrPayloads"]!!.jsonArray[0].jsonObject
        val json = v.s("json")!!
        val iat = Json.parseToJsonElement(json).jsonObject["iat"]!!.jsonPrimitive.long
        val exp = Json.parseToJsonElement(json).jsonObject["exp"]!!.jsonPrimitive.long
        fun enc(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())
        fun error(payload: String, now: Long = iat) = try {
            QrPayloads.parse(payload, now); null
        } catch (e: SoftTokenException) {
            e.error
        }
        assertEquals(SdkError.TRANSACTION_BINDING_MISMATCH, error(enc(json.replace("Bob Santoso", "Eve"))))
        assertEquals(SdkError.TRANSACTION_BINDING_MISMATCH, error(enc(json.replace("150000.00", "1500000.00"))))
        assertEquals(SdkError.CHALLENGE_EXPIRED, error(v.s("encoded")!!, exp))
        assertEquals(SdkError.UNSUPPORTED_VERSION, error(enc(json.replace("\"v\":1", "\"v\":2"))))
        assertEquals(SdkError.UNSUPPORTED_SUITE, error(enc(json.replace("QH64-T1M", "QH64-T2M"))))
        assertEquals(SdkError.INVALID_QR, error("not base64 at all!"))
        assertEquals(SdkError.INVALID_QR, error(enc("""{"v":1}""")))
    }
}
