package id.softtoken.sdk

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import java.util.Base64

/** Transaction bound into a challenge; canonical form txId|amount|currency|creditorAccount|creditorName|timestamp. */
data class Transaction(
    val txId: String,
    val amount: String,
    val currency: String,
    val creditorAccount: String,
    val creditorName: String,
    val timestamp: String,
) {
    fun canonical(): String = listOf(txId, amount, currency, creditorAccount, creditorName, timestamp).joinToString("|")

    /** SHA-256 of the canonical form (UTF-8) as 64 lowercase hex chars. */
    fun challenge(): String = sha256(canonical().toByteArray(Charsets.UTF_8)).toHex()
}

/** Sent by the app to its backend to start enrollment. */
data class EnrollmentRequest(val userId: String, val deviceId: String, val devicePublicKey: String)

/** Handshake data returned by the token service (relayed by the app's backend). */
data class EnrollmentResponse(
    val tokenId: String,
    val serverPublicKey: String,
    val salt: String,
    val suite: String,
    val activationChallenge: String,
)

data class ActivationChallenge(val tokenId: String, val challenge: String)

/** A validated QR payload: data shown to the user comes from here, never from a server response. */
data class ApprovalRequest(
    val challengeId: String,
    val suite: String,
    val challenge: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val transaction: Transaction,
)

enum class TokenStatus { NOT_ENROLLED, READY, NEEDS_REACTIVATION }

enum class SdkError {
    INVALID_QR, UNSUPPORTED_VERSION, UNSUPPORTED_SUITE, CHALLENGE_EXPIRED, TRANSACTION_BINDING_MISMATCH,
    NOT_ENROLLED, ENROLLMENT_FAILED, KEY_INVALIDATED, AUTHENTICATION_FAILED
}

class SoftTokenException(val error: SdkError, message: String, cause: Throwable? = null) : Exception(message, cause)

/** QR payload v1 (base64url JSON). Pure JVM so it is unit-testable. */
object QrPayloads {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Decodes and validates version, suite, expiry and the transaction hash binding.
     * @throws SoftTokenException before any key is touched if the payload must not be approved
     */
    fun parse(payload: String, nowEpochSeconds: Long): ApprovalRequest {
        val obj = try {
            json.parseToJsonElement(String(Base64.getUrlDecoder().decode(payload.trim()), Charsets.UTF_8)).jsonObject
        } catch (e: Exception) {
            throw SoftTokenException(SdkError.INVALID_QR, "QR is not a valid payload", e)
        }
        val version = obj.long("v")
        if (version != 1L) throw SoftTokenException(SdkError.UNSUPPORTED_VERSION, "Unsupported payload version $version")
        val suite = obj.str("suite")
        if (suite != OcraSuite.DEFAULT) throw SoftTokenException(SdkError.UNSUPPORTED_SUITE, "Unsupported suite")
        val tx = (obj["tx"] as? JsonObject) ?: throw SoftTokenException(SdkError.INVALID_QR, "tx missing")
        val transaction = Transaction(tx.str("txId"), tx.str("amount"), tx.str("currency"), tx.str("creditorAccount"),
            tx.str("creditorName"), tx.str("timestamp"))
        val ch = obj.str("ch")
        val exp = obj.long("exp")
        if (!MessageDigest.isEqual(transaction.challenge().toByteArray(), ch.lowercase().toByteArray())) {
            throw SoftTokenException(SdkError.TRANSACTION_BINDING_MISMATCH, "Transaction data does not match the challenge")
        }
        if (nowEpochSeconds >= exp) throw SoftTokenException(SdkError.CHALLENGE_EXPIRED, "Challenge expired")
        return ApprovalRequest(obj.str("cid"), suite, ch, obj.long("iat"), exp, transaction)
    }

    private fun JsonObject.str(k: String): String =
        (this[k] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotEmpty() }
            ?: throw SoftTokenException(SdkError.INVALID_QR, "$k missing")

    private fun JsonObject.long(k: String): Long =
        (this[k] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
            ?: throw SoftTokenException(SdkError.INVALID_QR, "$k missing")
}
