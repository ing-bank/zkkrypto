package com.ing.dlt.zkkrypto.ecc.mimc

import org.bouncycastle.jcajce.provider.digest.Keccak
import java.math.BigInteger


data class Mimc7Hash(
    val r: BigInteger,
    val numRounds: Int = defaultNumRounds,
    val roundConstants: List<BigInteger> = generateRoundConstants(r = r, numRounds = numRounds)
) {

    /**
     * Hash size in bytes
     */
    val hashLength = r.bitLength() / 8 + if(r.bitLength() / 8 != 0) 1 else 0

    fun hash(msg: ByteArray): ByteArray = hash(bytesToField(msg))

    fun hash(msg: List<BigInteger>): ByteArray {

        // check if all elements are in field R
        msg.forEach {
            if( it <= r) throw IllegalArgumentException("Element $it is not in field $r")
        }

        var result = BigInteger.ZERO

        msg.forEach {
            result = (result + it + hashElement(it, result)) % r
        }
        val bytes = result.toByteArray()
        return if(bytes.size == hashLength)
            bytes
        else
            ByteArray(hashLength - bytes.size).plus(bytes)
    }

    private fun hashElement(msg: BigInteger, key: BigInteger): BigInteger {
        var res: BigInteger = BigInteger.ZERO
        for (i in 0..numRounds) {
            val t = if (i == 0) {
                msg + key
            } else {
                res + key + roundConstants[i];
            }

            val t2 = t * t
            val t4 = t2 * t2
            res = (t4 * t2 * t) % r
        }
        return (res + key) % r
    }

    private fun bytesToField(msg: ByteArray): List<BigInteger> {
        TODO("Not yet implemented")
    }

    companion object {

        const val defaultNumRounds = 91
        val defaultSeed = "mimc".toByteArray()

        fun generateRoundConstants(seed: ByteArray = defaultSeed, numRounds: Int = defaultNumRounds, r: BigInteger): List<BigInteger> {

            val constants = mutableListOf<BigInteger>(BigInteger.ZERO)

            val keccak: Keccak.Digest256 = Keccak.Digest256()
            val digest = keccak.digest(seed)

            var c = BigInteger(1, digest)

            for (i in 0 until numRounds) {
                val bytes = dropSignBitIfNeeded(c.toByteArray())
                c = BigInteger(1, keccak.digest(bytes))
                constants.add(c % r)
            }
            return constants
        }

        private fun dropSignBitIfNeeded(bytes: ByteArray): ByteArray {
            return if (bytes[0] == 0.toByte()) {
                val res = ByteArray(bytes.size - 1)
                System.arraycopy(bytes, 1, res, 0, res.size)
                res
            } else bytes
        }
    }
}