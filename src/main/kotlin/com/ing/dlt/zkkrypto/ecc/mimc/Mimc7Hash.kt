package com.ing.dlt.zkkrypto.ecc.mimc

import com.ing.dlt.zkkrypto.ecc.ZKHash
import com.ing.dlt.zkkrypto.ecc.curves.BabyJubjub
import org.bouncycastle.jcajce.provider.digest.Keccak
import java.math.BigInteger
import kotlin.math.min


data class Mimc7Hash(
    val r: BigInteger = BabyJubjub.R,
    val numRounds: Int = defaultNumRounds,
    val roundConstants: List<BigInteger> = generateRoundConstants(r = r, numRounds = numRounds)
): ZKHash {

    /**
     * Hash size in bytes
     */
    override val hashLength = r.bitLength() / 8 + if(r.bitLength() / 8 != 0) 1 else 0

    override fun hash(msg: ByteArray): ByteArray = hash(bytesToField(msg))

    fun hash(msg: List<BigInteger>): ByteArray {

        // check if all elements are in field R
        msg.forEach {
            if( it > r) throw IllegalArgumentException("Element $it is not in field $r")
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
        for (i in 0 until numRounds) {
            val t = if (i == 0) {
                msg + key
            } else {
                res + key + roundConstants[i]
            }

            val t2 = t * t
            val t4 = t2 * t2
            res = (t4 * t2 * t) % r
        }
        return (res + key) % r
    }

    private fun bytesToField(msg: ByteArray): List<BigInteger> {

        // 31 seems to hardcoded and probably should depend on R but I use it like this for compatibility reason
        val n = 31
        val ints = mutableListOf<BigInteger>()

        for (i in msg.indices step n) {
            // We revert array here because bytes are supposed to be little-endian unlike BigInteger
            val int = BigInteger(1, msg.sliceArray(i until min(i+n, msg.size)).reversedArray())
            ints.add(int)
        }
        return ints
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