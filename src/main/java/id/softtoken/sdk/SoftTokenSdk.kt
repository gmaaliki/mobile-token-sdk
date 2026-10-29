package id.softtoken.sdk

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import androidx.biometric.BiometricPrompt
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Provides the authenticated [Mac] for one OCRA computation. Typical implementation:
 * BiometricPrompt.authenticate(promptInfo, cryptoObject) and return result.cryptoObject.
 * Throw (or let cancellation propagate) when the user cancels; no OCRA value is computed then.
 */
fun interface UserAuthenticator {
    suspend fun authenticate(cryptoObject: BiometricPrompt.CryptoObject): BiometricPrompt.CryptoObject
}

/**
 * Soft token on Android. No UI, no network: the app relays [EnrollmentRequest]/[EnrollmentResponse] and OCRA
 * values to its backend. The OCRA seed lives only in Android Keystore as a non-exportable HMAC-SHA256 key that
 * requires biometric authentication for every use.
 */
class SoftTokenSdk(
    context: Context,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val prefs = context.applicationContext.getSharedPreferences("id.softtoken.sdk", Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    // API < 31 has no Keystore ECDH; the ephemeral software key lives only between begin and complete.
    private var softwareAgreementKey: KeyPair? = null

    /** Creates the device EC P-256 key pair and returns its public key for the token service. */
    suspend fun beginEnrollment(userId: String, deviceId: String): EnrollmentRequest {
        val publicKey = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            g.initialize(KeyGenParameterSpec.Builder(ECDH_ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).build())
            g.generateKeyPair().public
        } else {
            val g = KeyPairGenerator.getInstance("EC")
            g.initialize(ECGenParameterSpec("secp256r1"))
            g.generateKeyPair().also { softwareAgreementKey = it }.public
        }
        prefs.edit().putString(KEY_USER, userId).putString(KEY_DEVICE, deviceId).apply()
        return EnrollmentRequest(userId, deviceId, Base64.getEncoder().encodeToString(publicKey.encoded))
    }

    /** ECDH + HKDF to the shared seed, imports it into Keystore (biometric-bound), wipes it from memory. */
    suspend fun completeEnrollment(response: EnrollmentResponse): ActivationChallenge {
        if (response.suite != OcraSuite.DEFAULT) throw SoftTokenException(SdkError.UNSUPPORTED_SUITE, "Unsupported suite")
        val serverKey = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(response.serverPublicKey)))
        } catch (e: Exception) {
            throw SoftTokenException(SdkError.ENROLLMENT_FAILED, "Invalid server public key", e)
        }
        val (agreement, privateKey) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE) to (keyStore.getKey(ECDH_ALIAS, null) as? PrivateKey)
        } else {
            KeyAgreement.getInstance("ECDH") to softwareAgreementKey?.private
        }
        privateKey ?: throw SoftTokenException(SdkError.ENROLLMENT_FAILED, "beginEnrollment was not called")
        var shared: ByteArray? = null
        var seed: ByteArray? = null
        try {
            agreement.init(privateKey)
            agreement.doPhase(serverKey, true)
            shared = agreement.generateSecret()
            seed = Hkdf.sha256(Base64.getDecoder().decode(response.salt), shared, Hkdf.seedInfo(response.tokenId), 32)
            keyStore.setEntry(HMAC_ALIAS, KeyStore.SecretKeyEntry(SecretKeySpec(seed, KeyProperties.KEY_ALGORITHM_HMAC_SHA256)),
                KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                    .setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(true)
                    .build())
        } catch (e: SoftTokenException) {
            throw e
        } catch (e: Exception) {
            throw SoftTokenException(SdkError.ENROLLMENT_FAILED, "Key agreement failed", e)
        } finally {
            shared?.fill(0)
            seed?.fill(0)
            softwareAgreementKey = null
            if (keyStore.containsAlias(ECDH_ALIAS)) keyStore.deleteEntry(ECDH_ALIAS)
        }
        prefs.edit().putString(KEY_TOKEN, response.tokenId).apply()
        return ActivationChallenge(response.tokenId, response.activationChallenge)
    }

    /** OCRA over the activation challenge (proof of possession); requires user authentication. */
    suspend fun activationProof(ch: ActivationChallenge, auth: UserAuthenticator): String = compute(ch.challenge, auth)

    /** Validates a scanned QR. Throws [SoftTokenException] before any biometric prompt if it must be rejected. */
    fun parseQr(payload: String): ApprovalRequest = QrPayloads.parse(payload, clock() / 1000)

    /** 8-digit OCRA response approving [req]; requires user authentication. */
    suspend fun approve(req: ApprovalRequest, auth: UserAuthenticator): String {
        if (clock() / 1000 >= req.expiresAt) throw SoftTokenException(SdkError.CHALLENGE_EXPIRED, "Challenge expired")
        return compute(req.challenge, auth)
    }

    fun tokenStatus(): TokenStatus {
        val key = keyStore.getKey(HMAC_ALIAS, null) as? SecretKey ?: return TokenStatus.NOT_ENROLLED
        return try {
            Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256).init(key)
            TokenStatus.READY
        } catch (e: KeyPermanentlyInvalidatedException) {
            TokenStatus.NEEDS_REACTIVATION
        }
    }

    /** tokenId stored at enrollment, or null. */
    fun tokenId(): String? = prefs.getString(KEY_TOKEN, null)

    /** Deletes the key and local state. The backend should revoke the token separately. */
    fun destroy() {
        listOf(HMAC_ALIAS, ECDH_ALIAS).forEach { if (keyStore.containsAlias(it)) keyStore.deleteEntry(it) }
        prefs.edit().clear().apply()
    }

    private suspend fun compute(question: String, auth: UserAuthenticator): String {
        val key = keyStore.getKey(HMAC_ALIAS, null) as? SecretKey
            ?: throw SoftTokenException(SdkError.NOT_ENROLLED, "No token on this device")
        val mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256)
        try {
            mac.init(key)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw SoftTokenException(SdkError.KEY_INVALIDATED, "Biometrics changed; reactivate the token", e)
        }
        val authenticated = try {
            auth.authenticate(BiometricPrompt.CryptoObject(mac)).mac
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            throw SoftTokenException(SdkError.AUTHENTICATION_FAILED, "User authentication failed", e)
        } ?: throw SoftTokenException(SdkError.AUTHENTICATION_FAILED, "No authenticated Mac")
        val suite = OcraSuite.parse(OcraSuite.DEFAULT)
        val step = suite.timeStep(clock() / 1000)
        return Ocra.generate(suite, Ocra.Input(question, step)) { _, data -> authenticated.doFinal(data) }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val HMAC_ALIAS = "id.softtoken.ocra"
        const val ECDH_ALIAS = "id.softtoken.ecdh"
        const val KEY_TOKEN = "tokenId"
        const val KEY_USER = "userId"
        const val KEY_DEVICE = "deviceId"
    }
}
