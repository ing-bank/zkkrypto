package com.ing.dlt.zkkrypto.ecc.schnorr

import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import com.ing.dlt.zkkrypto.ecc.schnorr.FixedGenerators.altBabyJubjubFixedGenerators
import com.ing.dlt.zkkrypto.util.asUnsigned
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.digests.Blake2sDigest
import java.math.BigInteger
import java.security.SecureRandom
import kotlin.random.Random.Default.nextBytes

enum class Hash{
    BLAKE2S,
    BLAKE2B
}

/**
 * Implementation of Schnorr signatures
 * This implementation uses AltBabyJubJub curve and Blake2 hash
 */

class SchnorrSignature (
    val curve: EllipticCurve,
    val base: EllipticCurvePoint,
    val compPersonalization: ByteArray,
    val msgPersonalization: ByteArray) {

    companion object {
        fun zinc() = SchnorrSignature(
            curve = AltBabyJubjub,
            base = altBabyJubjubFixedGenerators()[5],
            compPersonalization = "Zcash_RedJubjubH".toByteArray(),
            msgPersonalization = "Matter_H".toByteArray()
        )

        const val MAX_MESSAGE_SIZE = 32
        const val BLAKE2B_DIGEST_LENGTH = 64
        const val BLAKE2S_DIGEST_LENGTH = 32
    }

    private lateinit var privateKey: BigInteger
    lateinit var publicKey: EllipticCurvePoint

    fun generatePrivateKey() {
        privateKey = BigInteger(curve.S.bitLength(), SecureRandom())
        while (privateKey > curve.S) {
            privateKey = BigInteger(curve.S.bitLength(), SecureRandom())
        }
    }

    fun getPublicKeyFromPrivate(){
        publicKey = base.scalarMult(privateKey)
    }

    fun signRawMessage(msgBytes: ByteArray) : Signature {

        //Get random bytes
        val t = nextBytes(80)

        //Generate random r as the hash digest of Blake2b(t || msg)
        val r = hashToScalar(Hash.BLAKE2B, compPersonalization, first = t, second = msgBytes)

        //compute first component of the signature
        val rPoint = base.scalarMult(r)

        //pad message
        val paddedMessage = msgBytes + ByteArray(MAX_MESSAGE_SIZE - msgBytes.size)
        val uniformMessage = toUniformFieldElement(paddedMessage)

        //second component of the signature
        val s = uniformMessage.multiply(privateKey).mod(curve.S).add(r).mod(curve.S)

        return Signature(rPoint, s)
    }

    fun signHashedMessage(msgBytes: ByteArray) : Signature {

        val t = nextBytes(80)
        val r = hashToScalar(Hash.BLAKE2B, compPersonalization, first = t, second = msgBytes)

        //compute first component of the signature
        val rPoint = base.scalarMult(r)

        //hash r_x || message
        val rXCoordBytes = rPoint.x.toByteArray().reversedArray()
        val paddedMessage = msgBytes + ByteArray(MAX_MESSAGE_SIZE - msgBytes.size)

        val messageDigest = hashToScalar(Hash.BLAKE2S, msgPersonalization, first = rXCoordBytes, second = paddedMessage)

        //second component of the signature
        val s = messageDigest.multiply(privateKey).mod(curve.S).add(r).mod(curve.S)

        return Signature(rPoint, s)
    }

    fun verifyRawMessage(msgBytes: ByteArray, signature: Signature) : Boolean {
        //pad message to max message size and convert to a field element
        val paddedMessage = msgBytes + ByteArray(MAX_MESSAGE_SIZE - msgBytes.size)
        val uniformMessage = toUniformFieldElement(paddedMessage)

        val baseMultS = base.scalarMult(signature.s)
        val pkMultMsg = publicKey.scalarMult(uniformMessage)
        val rhs = pkMultMsg.add(signature.r)

        return rhs == baseMultS
    }

    fun verifyHashedMessage(msgBytes: ByteArray, signature: Signature) : Boolean {
        //hash r_x || message
        val rXCoordBytes = signature.r.x.toByteArray().reversedArray()
        val paddedMessage = msgBytes + ByteArray(MAX_MESSAGE_SIZE - msgBytes.size)

        val messageDigest = hashToScalar(Hash.BLAKE2S, msgPersonalization, first = rXCoordBytes, second = paddedMessage)

        //verification
        val baseMultS = base.scalarMult(signature.s)
        val pkMultMsg = publicKey.scalarMult(messageDigest)
        val rhs = pkMultMsg.add(signature.r)

        return rhs == baseMultS
    }

    private fun hashToScalar(hashFunction: Hash, personalization: ByteArray, first: ByteArray, second:ByteArray) : BigInteger {
        val digest = when (hashFunction) {
            Hash.BLAKE2B -> hashBlake2b(first + second, personalization);
            Hash.BLAKE2S -> hashBlake2s(first.plus(second), personalization)
        }
        return toUniformFieldElement(digest)
    }

    private fun toUniformFieldElement(value: ByteArray): BigInteger = value
        .reversedArray()
        .fold(BigInteger.ZERO) { acc, byte ->
            val ubyte = byte.asUnsigned()
            (7 downTo 0).fold(acc) { local, shift ->
                val bit = ubyte shr shift and 1
                (local + local) % curve.S + if (bit == 1) { BigInteger.ONE } else { BigInteger.ZERO }
            }
        }

    private fun hashBlake2b(bytes: ByteArray, personalization: ByteArray): ByteArray {
        val blake2b = Blake2bDigest(null, BLAKE2B_DIGEST_LENGTH, null, personalization)
        blake2b.reset()
        blake2b.update(bytes, 0, bytes.size)
        val hash = ByteArray(BLAKE2B_DIGEST_LENGTH)
        blake2b.doFinal(hash, 0)
        return hash
    }

    private fun hashBlake2s(bytes: ByteArray, personalization: ByteArray): ByteArray {
        val blake2s = Blake2sDigest(null, BLAKE2S_DIGEST_LENGTH, null, personalization)
        blake2s.reset()
        blake2s.update(bytes, 0, bytes.size)
        val hash = ByteArray(BLAKE2S_DIGEST_LENGTH)
        blake2s.doFinal(hash, 0)
        return hash
    }

}

