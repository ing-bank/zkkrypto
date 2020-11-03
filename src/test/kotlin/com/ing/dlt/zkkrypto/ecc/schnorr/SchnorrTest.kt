package com.ing.dlt.zkkrypto.ecc.schnorr

import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.random.Random.Default.nextBytes
import kotlin.system.measureNanoTime

class SchnorrSignatureTest {

    @Test
    fun `test raw message signing from Zinc`() {

        listOf(ByteArray(1) { 85 }, "Foo bar pad to16".toByteArray()).forEach {
            val schnorr = SchnorrSignature.zinc

            println("\nPublic Key:")
            println("\tx coord = " + schnorr.publicKey.x.toString(16))
            println("\ty coord = " + schnorr.publicKey.y.toString(16) + "\n")

            val signature = schnorr.signRawMessage(msgBytes = it, seed = nextBytes(80))

            println("Signature:")
            println("\tR:")
            println("\t\tx coord = " + signature.r.x.toString(16))
            println("\t\ty coord = " + signature.r.y.toString(16))
            println("\ts:")
            println("\t\tvalue = " + signature.s.toString(16))

            val verified = schnorr.verifyRawMessage(it, signature)

            if (verified)
                println("\nSignature verified!")

            assert(verified)
        }
    }

    @Test
    fun `test hashed message signing from Zinc`() {

        listOf(ByteArray(1) { 85 }, "Foo bar pad to16".toByteArray()).forEach {
            val schnorr = SchnorrSignature.zinc

            println("Public Key:")
            println("\tx coord = " + schnorr.publicKey.x.toString(16))
            println("\ty coord = " + schnorr.publicKey.y.toString(16) + "\n")

            val signature = schnorr.signHashedMessage(msgBytes = it, seed = nextBytes(80))
            val verified = schnorr.verifyHashedMessage(it, signature)

            println("Signature:")
            println("\tR:")
            println("\t\tx coord = " + signature.r.x.toString(16))
            println("\t\ty coord = " + signature.r.y.toString(16))
            println("\ts:")
            println("\t\tvalue = " + signature.s.toString(16))

            if (verified)
                println("Signature verified!")

            assert(verified)
        }
    }

    @Test
    fun testVectorsPlainMessage() {

        val schnorr = SchnorrSignature.zinc

        TestVectors.testVectorsPlainMessage.forEach { vector ->

            schnorr.setKeys(BigInteger(vector.privateKey, 16))
            val signature = schnorr.signRawMessage(
                msgBytes = vector.message.toByteArray(),
                seed = vector.seed.split(",").map { it.toInt().toByte() }.toByteArray()
            )

            assertEquals(BigInteger(vector.signatureRX, 16), signature.r.x)
            assertEquals(BigInteger(vector.signatureRY, 16), signature.r.y)

            assertEquals(BigInteger(vector.signatureS, 16), signature.s)

            println("Validated!")
        }
    }

    @Test
    fun testVectorsHashedMessage() {

        val schnorr = SchnorrSignature.zinc

        TestVectors.testVectorsHashedMessage.forEach { vector ->

            schnorr.setKeys(BigInteger(vector.privateKey, 16))
            val signature = schnorr.signHashedMessage(
                msgBytes = vector.message.toByteArray(),
                seed = vector.seed.split(",").map { it.toInt().toByte() }.toByteArray()
            )

            assertEquals(BigInteger(vector.signatureRX, 16), signature.r.x)
            assertEquals(BigInteger(vector.signatureRY, 16), signature.r.y)

            assertEquals(BigInteger(vector.signatureS, 16), signature.s)

            println("Validated!")
        }
    }

    @Test
    @Tag("benchmark")
    fun benchmarkRawMessage() {
        val numRuns = 1000
        val schnorr = SchnorrSignature.zinc

        var keyGenTimeElapsed: Long = 0
        var signTimeElapsed: Long = 0
        var verifyTimeElapsed: Long = 0

        for (m in 1..numRuns) {

            // measure KeyGen
            keyGenTimeElapsed += measureNanoTime {
                schnorr.nextKeyPair()
            }

            // measure sign
            var signature = Signature(AltBabyJubjub.zero, BigInteger.ZERO)

            signTimeElapsed += measureNanoTime {
                signature = schnorr.signRawMessage(msgBytes = byteArrayOf(m.toByte()), seed = nextBytes(80))
            }

            // measure verify
            verifyTimeElapsed += measureNanoTime {
                schnorr.verifyRawMessage(byteArrayOf(m.toByte()), signature)
            }
        }

        println("Key generation:")
        println("Total time (nanos): $keyGenTimeElapsed")
        println("Average time per operation (nanos): ${keyGenTimeElapsed / numRuns}\n\n")

        println("Sign Raw Message:")
        println("Total time (nanos): $signTimeElapsed")
        println("Average time per operation (nanos): ${signTimeElapsed / numRuns}\n\n")

        println("Verify Raw Message:")
        println("Total time (nanos): $verifyTimeElapsed")
        println("Average time per operation (nanos): ${verifyTimeElapsed / numRuns}\n\n")
    }

    @Test
    @Tag("benchmark")
    fun benchmarkHashedMessage() {
        val numRuns = 1000
        val schnorr = SchnorrSignature.zinc

        var keyGenTimeElapsed: Long = 0
        var signTimeElapsed: Long = 0
        var verifyTimeElapsed: Long = 0

        for (m in 1..numRuns) {

            // measure KeyGen
            keyGenTimeElapsed += measureNanoTime {
                schnorr.nextKeyPair()
            }

            // measure sign
            var signature = Signature(AltBabyJubjub.zero, BigInteger.ZERO)

            signTimeElapsed += measureNanoTime {
                signature = schnorr.signHashedMessage(msgBytes = byteArrayOf(m.toByte()), seed = nextBytes(80))
            }

            // measure verify
            verifyTimeElapsed += measureNanoTime {
                schnorr.verifyHashedMessage(byteArrayOf(m.toByte()), signature)
            }
        }

        println("Key generation:")
        println("Total time (nanos): $keyGenTimeElapsed")
        println("Average time per operation (nanos): ${keyGenTimeElapsed / numRuns}\n\n")

        println("Sign Hashed Message:")
        println("Total time (nanos): $signTimeElapsed")
        println("Average time per operation (nanos): ${signTimeElapsed / numRuns}\n\n")

        println("Verify Hashed Message:")
        println("Total time (nanos): $verifyTimeElapsed")
        println("Average time per operation (nanos): ${verifyTimeElapsed / numRuns}\n\n")
    }
}
