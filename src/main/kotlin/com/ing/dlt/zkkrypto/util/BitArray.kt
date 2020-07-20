package com.ing.dlt.zkkrypto.util

import java.lang.IllegalArgumentException
import java.lang.IllegalStateException
import java.math.BigInteger

/**
 * Bit array with underlying bit[] representation
 * Bir order:
 * zero (2^0) bit of data[0] is a first bit of the sequence;
 * last (2^7) bit of data[data.size-1] is the last bit of sequence (unless size != data.size * 8)
 */
data class BitArray(val data: ByteArray, val size: Int = data.size * 8) {

    fun get(i: Int): BigInteger {
        return if(testBit(i)) BigInteger.ONE else BigInteger.ZERO
    }

    fun testBit(i: Int): Boolean {
        if(i >= size) throw ArrayIndexOutOfBoundsException(i)
        val byte: Int = i / 8
        val bit: Int = i % 8
        return data[byte].toInt().ushr(bit).and(1) > 0
    }

    fun withPadding(numBits: Int): BitArray {
        val newSize = size + numBits
        val byteLenDiff = wordLen(newSize) - data.size
        return BitArray(data.plus(ByteArray(byteLenDiff)), newSize)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BitArray

        if (!data.contentEquals(other.data)) return false
        if (size != other.size) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + size
        return result
    }

    fun plus(other: BitArray): BitArray {
        // To do: implement arbitrary length if we need such
        if(size % 8 != 0) throw IllegalStateException("Length should be multiple of 8")

        return BitArray(data.plus(other.data), size + other.size)
    }

    companion object {

        fun fromString(bitString: String) : BitArray {

            val byteLen = wordLen(bitString.length)
            val data = ByteArray(byteLen)

            var bitIndex = 0
            var byteIndex = 0

            bitString.forEach { char ->
                if(char == '1') {
                    data[byteIndex] = (data[byteIndex] + 1.shl(bitIndex)).toByte()
                } else if(char != '0') throw IllegalArgumentException("Only binary strings are allowed")

                bitIndex++
                if(bitIndex == 8) {
                    byteIndex++
                    bitIndex = 0
                }
            }

            return BitArray(data, bitString.length)
        }

        fun wordLen(bitLen: Int, wordLen: Int = 8): Int {
            return bitLen / wordLen + if(bitLen % wordLen == 0) 0 else 1
        }
    }
}