package com.ing.dlt.zkkrypto.ecc.schnorr

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import com.ing.dlt.zkkrypto.ecc.curves.Jubjub
import com.ing.dlt.zkkrypto.ecc.pedersenhash.PedersenHash
import com.ing.dlt.zkkrypto.util.BitArray
import org.junit.jupiter.api.Test
import java.math.BigInteger


class SchnorrSignatureTest {

    @Test
    fun `test raw message signing`(){

        val schnorr = SchnorrSignature.zinc()

        schnorr.generatePrivateKey()
        schnorr.getPublicKeyFromPrivate()

        println("Public Key:")
        println("\tx coord = " + schnorr.publicKey.x.toString(16))
        println("\ty coord = " + schnorr.publicKey.y.toString(16) + "\n")

        val msg = 85.toByte()
        val msgBytes = byteArrayOf(msg)

        //val msg = "Foo bar pad to16"
        //val msgBytes = msg.toByteArray()

        val signature = schnorr.signRawMessage(msgBytes);

        println("Signature:")
        println("\tR:")
        println("\t\tx coord = " + signature.r.x.toString(16))
        println("\t\ty coord = " + signature.r.y.toString(16))
        println("\ts:")
        println("\t\tvalue = " + signature.s.toString(16))


        val verified = schnorr.verifyRawMessage(msgBytes, signature)

        if (verified)
            println("\nSignature verified!")

        assert(verified)
    }

    @Test
    fun `test hashed message signing`(){

        val schnorr = SchnorrSignature.zinc()

        schnorr.generatePrivateKey()
        schnorr.getPublicKeyFromPrivate()

        println("Public Key:")
        println("\tx coord = " + schnorr.publicKey.x.toString(16))
        println("\ty coord = " + schnorr.publicKey.y.toString(16) + "\n")

        val msg = 85.toByte()
        val msgBytes = byteArrayOf(msg)

        //val msg = "Foo bar pad to16"
        //val msgBytes = msg.toByteArray()

        val signature = schnorr.signHashedMessage(msgBytes);
        val verified = schnorr.verifyHashedMessage(msgBytes, signature)

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

    //@Test
    fun benchmarkRawMessage() {
        val numRuns = 1000
        val schnorr = SchnorrSignature.zinc()

        var startKeyGen:Long = 0
        var finishKeyGen:Long = 0

        var startSign:Long = 0
        var finishSign:Long = 0

        var startVerify:Long = 0
        var finishVerify:Long = 0

        for(m in 1..numRuns) {

            //measure KeyGen
            startKeyGen += System.nanoTime()

            schnorr.generatePrivateKey()
            schnorr.getPublicKeyFromPrivate()

            finishKeyGen += System.nanoTime()

            //measure sign raw message
            startSign += System.nanoTime()
            val signature = schnorr.signRawMessage(byteArrayOf(m.toByte()))
            finishSign += System.nanoTime()

            //measure verify
            startVerify += System.nanoTime()
            schnorr.verifyRawMessage(byteArrayOf(m.toByte()), signature)
            finishVerify += System.nanoTime()
        }

        println("Key generation:")
        println("Total time (nanos): ${finishKeyGen - startKeyGen}")
        println("Average time per operation (nanos): ${(finishKeyGen - startKeyGen) / numRuns}\n\n")

        println("Sign Raw Message:")
        println("Total time (nanos): ${finishSign - startSign}")
        println("Average time per operation (nanos): ${(finishSign - startSign) / numRuns}\n\n")

        println("Verify Raw Message:")
        println("Total time (nanos): ${finishVerify - startVerify}")
        println("Average time per operation (nanos): ${(finishVerify - startVerify) / numRuns}\n\n")

    }

    //@Test
    fun benchmarkSignedMessage() {
        val numRuns = 1000
        val schnorr = SchnorrSignature.zinc()

        var startKeyGen:Long = 0
        var finishKeyGen:Long = 0

        var startSign:Long = 0
        var finishSign:Long = 0

        var startVerify:Long = 0
        var finishVerify:Long = 0

        for(m in 1..numRuns) {

            //measure KeyGen
            startKeyGen += System.nanoTime()

            schnorr.generatePrivateKey()
            schnorr.getPublicKeyFromPrivate()

            finishKeyGen += System.nanoTime()

            //measure sign raw message
            startSign += System.nanoTime()
            val signature = schnorr.signHashedMessage(byteArrayOf(m.toByte()))
            finishSign += System.nanoTime()

            //measure verify
            startVerify += System.nanoTime()
            schnorr.verifyHashedMessage(byteArrayOf(m.toByte()), signature)
            finishVerify += System.nanoTime()
        }

        println("Key generation:")
        println("Total time (nanos): ${finishKeyGen - startKeyGen}")
        println("Average time per operation (nanos): ${(finishKeyGen - startKeyGen) / numRuns}\n\n")

        println("Sign Hashed Message:")
        println("Total time (nanos): ${finishSign - startSign}")
        println("Average time per operation (nanos): ${(finishSign - startSign) / numRuns}\n\n")

        println("Verify Hashed Message:")
        println("Total time (nanos): ${finishVerify - startVerify}")
        println("Average time per operation (nanos): ${(finishVerify - startVerify) / numRuns}\n\n")
    }
}