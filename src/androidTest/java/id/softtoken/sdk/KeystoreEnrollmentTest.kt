package id.softtoken.sdk

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.KeyAgreement

/** Runs on an emulator/device: Keystore import works. OCRA itself needs a biometric, so it is covered by JVM tests. */
@RunWith(AndroidJUnit4::class)
class KeystoreEnrollmentTest {

    @Test
    fun enrollmentImportsSeedIntoKeystore() = runBlocking {
        val sdk = SoftTokenSdk(InstrumentationRegistry.getInstrumentation().targetContext)
        sdk.destroy()
        val req = sdk.beginEnrollment("u1", "d1")

        // act as the server: ephemeral key + ECDH, like soft-token-core
        val server = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val devicePub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(req.devicePublicKey)))
        KeyAgreement.getInstance("ECDH").apply { init(server.private); doPhase(devicePub, true) }.generateSecret()

        val ch = sdk.completeEnrollment(EnrollmentResponse("tok-1", Base64.getEncoder().encodeToString(server.public.encoded),
            Base64.getEncoder().encodeToString(ByteArray(16)), OcraSuite.DEFAULT, "00".repeat(32)))
        assertEquals("tok-1", ch.tokenId)
        assertEquals(TokenStatus.READY, sdk.tokenStatus())
        sdk.destroy()
        assertEquals(TokenStatus.NOT_ENROLLED, sdk.tokenStatus())
    }
}
