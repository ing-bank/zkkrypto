package com.ing.dlt.zkkrypto.ecc.pedersenhash

import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.ZKHash
import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import com.ing.dlt.zkkrypto.ecc.curves.Jubjub
import com.ing.dlt.zkkrypto.util.BitArray
import java.lang.IllegalStateException
import java.math.BigInteger
import kotlin.math.min

/**
 * Instance of Pedersen Hash.
 * Window size is dynamic by design but in practice it is only tested and works for classic 3-bits window
 */
data class PedersenHash(
    val window: Int = 3,
    val chunksPerGenerator: Int = 63, // ZCash default, Zinc uses 62 for AltJJ
    val curve: EllipticCurve,
    val generators: Generators = Generators.defaultForCurve(curve),
    val defaultSalt: BitArray? = null
): ZKHash {

    init {
        if(window != 3) throw IllegalStateException("Only supporting window size 3 at the moment")
    }

    private val chunkShift = window + 1

    /**
     * Hash size in bytes
     */
    override val hashLength = curve.S.toByteArray().size

    override fun hash(msg: ByteArray): ByteArray = hash(msg, salt = null)

    fun hash(msg: ByteArray, salt: BitArray? = defaultSalt): ByteArray = hash(BitArray(msg), salt)

    fun hash(msg: BitArray, salt: BitArray? = defaultSalt): ByteArray {

        var hashPoint = curve.zero
        val salted = salted(msg, salt)

        if(salted.size > maxBitLength() && maxBitLength() > 0) throw IllegalArgumentException("Message is too long, length = ${salted.size}, limit = ${maxBitLength()}")

        val m = padded(salted)

        val numProducts = numProducts(m)
        val generatorsIter = generators.iterator()

        for (i in 0 until numProducts) {
                hashPoint = hashPoint.add(generatorsIter.next().scalarMult(product(m, i)))
        }

        // we want constant size hashes so we add trailing zero bytes to the beginning
        val bytes = hashPoint.x.toByteArray()
        return if(bytes.size == hashLength)
            bytes
        else
            ByteArray(hashLength - bytes.size).plus(bytes)
    }

    // compute enc(m_j) as in the documentation
    private fun chunk(m: BitArray, productIndex: Int, chunkIndex: Int): BigInteger {
        val lowestBitIndex = (productIndex * chunksPerGenerator + chunkIndex) * window

        var chunk = BigInteger.ONE
        for(i in 0 until window-1) {
            chunk += m.get(lowestBitIndex + i).shiftLeft(i)
        }

        if(m.testBit(lowestBitIndex + (window-1))) {
            // only works for ZCash 3-bits window now because iden3 4-bit algorithm uses different sign switch :shrug:
            chunk = chunk.negate()
        }

        return chunk
    }

    private fun fieldNegate(element: BigInteger): BigInteger {
        return if(element >= BigInteger.ZERO) {
            element
        } else {
            curve.S + element
        }
    }

    // compute <M_i> as in the documentation
    private fun product(msg: BitArray, i: Int): BigInteger {

        var product = BigInteger.ZERO

        for(j in 0 until numChunksInProduct(msg, i)) {
            val chunk = fieldNegate(chunk(msg, i, j).shiftLeft(chunkShift * j))
            product += chunk
        }

        return product.mod(curve.S)
    }

    // chunksPerGenerator in most cases but variable for last product (it can be shorter)
    private fun numChunksInProduct(msg: BitArray, productIndex: Int): Int {

        val lastProduct = if(msg.size % productBitSize() == 0) msg.size / productBitSize() - 1 else msg.size / productBitSize()

        return if(productIndex == lastProduct) {
            if(msg.size % productBitSize() == 0)
                chunksPerGenerator
            else {
                msg.size % productBitSize() / window + if(msg.size % window == 0) 0 else 1
            }
        } else chunksPerGenerator
    }

    private fun productBitSize(): Int {
        return chunksPerGenerator * window
    }

    private fun maxBitLength(): Int {
        return generators.size * productBitSize()
    }

    private fun numProducts(m: BitArray) = m.size / productBitSize() + if(m.size % productBitSize() == 0) 0 else 1

    private fun salted(msg: BitArray, salt: BitArray?): BitArray {
        return salt?.plus(msg) ?: msg
    }

    private fun padded(m: BitArray): BitArray {
        return m.withPadding((window - m.size % window) % window)
    }

    companion object {
        val zinc = PedersenHash(
            curve = AltBabyJubjub,
            chunksPerGenerator = 62,
            defaultSalt = BitArray.fromString("111111")
        )

        fun zcash() = PedersenHash(curve = Jubjub, chunksPerGenerator = 63)
    }
}

