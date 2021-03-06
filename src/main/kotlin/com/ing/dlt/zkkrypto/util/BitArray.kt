package com.ing.dlt.zkkrypto.util

import java.math.BigInteger

/**
 * Bit array with underlying byte[] representation in big-endian bit order
 */
data class BitArray(val data: ByteArray, val size: Int = data.size * 8) {

    fun get(i: Int): BigInteger {
        return if(testBit(i)) BigInteger.ONE else BigInteger.ZERO
    }

    fun testBit(i: Int): Boolean {
        if(i >= size) throw ArrayIndexOutOfBoundsException(i)
        val byte: Int = i / 8
        val bit: Int = 7 - i % 8
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
        return if(size % 8 != 0) {
            val newData = shift(other, this.size).data
            for (i in this.data.indices) newData[i] = newData[i] or data[i]
            BitArray(newData, this.size + other.size)
        } else {
            BitArray(data.plus(other.data), this.size + other.size)
        }
    }


    companion object {

        fun fromString(bitString: String) : BitArray {

            val byteLen = wordLen(bitString.length)
            val data = ByteArray(byteLen)

            var bitIndex = 7
            var byteIndex = 0

            bitString.forEach { char ->
                if(char == '1') {
                    data[byteIndex] = (data[byteIndex] + 1.shl(bitIndex)).toByte()
                } else if(char != '0') throw IllegalArgumentException("Only binary strings are allowed")

                bitIndex--
                if(bitIndex < 0) {
                    byteIndex++
                    bitIndex = 7
                }
            }

            return BitArray(data, bitString.length)
        }

        private fun wordLen(bitLen: Int, wordLen: Int = 8): Int {
            return bitLen / wordLen + if(bitLen % wordLen == 0) 0 else 1
        }

        private fun shift(sourceBits: BitArray, bitCount: Int): BitArray {
            val shiftMod = bitCount % 8
            val offsetBytes = bitCount / 8
            val destBitSize = sourceBits.size + bitCount
            val byteSize = wordLen(destBitSize)
            val dest = ByteArray(byteSize)
            val carryMask = (0xFF ushr (8 - shiftMod)).toByte()
            val byteAdded = wordLen(sourceBits.size) != byteSize

            val source = sourceBits.data

            for (i in source.indices) {
                if(shiftMod == 0) {
                    dest[offsetBytes + i] = source[i]
                } else {
                    val sourceCarry = (source[i] and carryMask).asUnsigned() shl (8 - shiftMod)
                    dest[offsetBytes + i] = dest[offsetBytes + i] or (source[i].asUnsigned() ushr shiftMod).toByte()
                    if(!byteAdded && i == source.size - 1) { /* skip last carry if we don't add byte */ } else {
                        dest[offsetBytes + i + 1] = dest[offsetBytes + i + 1] or sourceCarry.toByte()
                    }
                }
            }
            return BitArray(dest, destBitSize)
        }

    }
}