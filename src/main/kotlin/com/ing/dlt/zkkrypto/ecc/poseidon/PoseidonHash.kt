package com.ing.dlt.zkkrypto.ecc.poseidon

import com.ing.dlt.zkkrypto.ecc.poseidon.Constants.Companion.defaultRoundConstants
import java.math.BigInteger
import kotlin.math.min

data class PoseidonHash(
    val r: BigInteger,
    val constants: Constants = defaultRoundConstants()
) {

    /**
     * Hash size in bytes
     */
    val hashLength = r.bitLength() / 8 + if(r.bitLength() / 8 != 0) 1 else 0

 //   fun hash(msg: ByteArray): ByteArray = hash(bytesToField(msg))

    private fun sbox(m: BigInteger): BigInteger {
        return m.modPow(BigInteger.valueOf(5), r)
    }

    fun mix(state: List<BigInteger>, matrix: List<List<BigInteger>>): List<BigInteger> {

        val newState: MutableList<BigInteger> = MutableList(state.size) { BigInteger.ZERO }

        for (i in state.indices) {
            for (j in state.indices) {
                newState[i] = newState[i] + matrix[j][i] * state[j]
            }
        }
        return newState
    }

    fun hash(msg: List<BigInteger>): BigInteger  {

        if (msg.isEmpty() || msg.size >= constants.numRoundsP.size - 1)
            throw Exception("Invalid inputs length: ${msg.size}, maximum allowed: ${constants.numRoundsP.size - 2}")

        val t = msg.size + 1

        var state = msg.plus(BigInteger.ZERO).toMutableList()

        val nRoundsP = constants.numRoundsP[t-2]

        val lastRound = constants.numRoundsF + nRoundsP - 1

        for (round in 0..constants.numRoundsF + nRoundsP) {

            // Add Round Key
            for (i in state.indices) {
                state[i] = state[i] + constants.c[t-2][round * t + i]
            }

            // S-Box
            if (round < constants.numRoundsF / 2 || round >= constants.numRoundsF / 2 + nRoundsP) {
                // Full round
                for (i in state.indices) {
                    state[i] = sbox(state[i])
                }
            } else {
                // Partial round
                state[0] = sbox(state[0])
            }

            // If not last round: mix (via matrix multiplication)
            if (round != lastRound) {
                state = mix(state, constants.m[t-2]).toMutableList()
            }
        }

        return state[0]
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
}