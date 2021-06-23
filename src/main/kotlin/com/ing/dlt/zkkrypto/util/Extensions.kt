package com.ing.dlt.zkkrypto.util

import java.math.BigInteger

fun Byte.asUnsigned() = this.toInt() and 0xFF

/** Performs a bitwise AND operation between the two values. */
infix fun Byte.and(other: Byte): Byte = (this.toInt() and other.toInt()).toByte()

/** Performs a bitwise OR operation between the two values. */
infix fun Byte.or(other: Byte): Byte = (this.toInt() or other.toInt()).toByte()

fun BigInteger.sqrtMod(generator: BigInteger, modulus: BigInteger): BigInteger? {
    when {
        modulus % BigInteger.valueOf(16) == BigInteger.valueOf(1) -> {
            // Tonelli-Shank's algorithm for q mod 16 = 1
            // https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
            val a = this

            // PRECOMPUTATION

            // q - 1 = t * 2^S, where q is modulus
            val (t, s) = breakdownModulus(modulus)

            val ONE = BigInteger.ONE
            val TWO = BigInteger.valueOf(2)
            var z = generator.modPow(t, modulus) // Root of unity
            val exp1 = TWO.modPow(s - ONE, modulus) // 2 ^ (s - 1)

            // COMPUTATION
            var w = a.modPow((t - ONE) / TWO, modulus)
            val a0 = (w.pow(2) * a).modPow(exp1, modulus)

            if ((a0 + ONE) % modulus == BigInteger.ZERO) return null

            var v = s
            var x = (a * w) % modulus
            var b = (x * w) % modulus

            // TODO optimise performance
            while (b != ONE) {
                val k = findK(b, v, modulus)
                w = z.modPow(TWO.modPow(v - k - ONE, modulus), modulus)
                z = w.modPow(TWO, modulus)
                b = (b * z) % modulus
                x = (x * w) % modulus
                v = k
            }
            return x
        }
        else -> error("General case is not yet implemented")
    }
}

/**
 * Find least integer k ≥ 0 such that b^2^k == 1
 */
private fun findK(b: BigInteger, limit: BigInteger, modulus: BigInteger): BigInteger {
    var k = BigInteger.ZERO
    do {
        val b2k = b.modPow(BigInteger.valueOf(2).modPow(k, modulus), modulus)
        if(b2k == BigInteger.ONE) return k else k++
    } while (k <= limit)
    error("K not found")
}

private fun breakdownModulus(q: BigInteger): Pair<BigInteger, BigInteger> {
    val qMinus1 = q - BigInteger.ONE
    var s = 0

    while(!qMinus1.testBit(s)) {
        s++
    }
    return qMinus1.shiftRight(s) to BigInteger.valueOf(s.toLong())
}