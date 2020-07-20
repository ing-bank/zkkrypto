package com.ing.dlt.zkkrypto.ecc.pedersenhash

import com.ing.dlt.zkkrypto.util.BitArray
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import java.math.BigInteger
import kotlin.random.Random

internal class PedersenHashTest {

    @Test
    fun hash() {

        TestVectors.vectors.forEach { vector ->

            val hash  = BigInteger(PedersenHash().hash(vector.input_bits))

            assertEquals(BigInteger(vector.hash_x, 16), hash)
        }
    }


    @Test
    fun constantSizeHash() {

//        PH(48058) = 004dfcf879a397d2e531f57282a5ef770953210f4e5030bc0d4526cf47fa2d00
//        48058 hashes to the point where X coordinate is only 31 byte long
//        so we check it was correctly padded with zero byte at zero position to be 32-bytes constant size

        val m = 48058
        val hash = PedersenHash().hash(BitArray(m.toBigInteger().toByteArray()))
        assertEquals(hash[0], 0)
        assertEquals(32, hash.size)
        assertEquals("4dfcf879a397d2e531f57282a5ef770953210f4e5030bc0d4526cf47fa2d00", BigInteger(hash).toString(16))
    }


    @Test
    fun salt() {

        val full = Random.Default.nextBytes(ByteArray(10))

        val expected = PedersenHash().hash(full)

        val msg = full.drop(4).toByteArray()
        val salt = full.dropLast(full.size - 4).toByteArray()

        val hash = PedersenHash().hash(msg, salt)

        assertArrayEquals(expected, hash)
    }


    //    @Test
    fun hashSingle() {

        val vector = TestVectors.vectors[0]

        val hash = BigInteger(PedersenHash().hash(vector.input_bits))

        println("Message hash is: ${hash.toString(16)}")

        assertEquals(BigInteger(vector.hash_x, 16), hash)

    }


//    @Test
    fun benchmark() {
// From https://github.com/zcash-hackworks/sapling-crypto/pull/79 :
//
//        at first:
//
//        test bench_pedersen_hash ... bench:     452,241 ns/iter (+/- 24,567)
//
//        after wnaf:
//
//        test bench_pedersen_hash ... bench:     276,877 ns/iter (+/- 7,185)
//
//        after more optimal doubling (eyeroll at the variance):
//
//        test bench_pedersen_hash ... bench:     279,210 ns/iter (+/- 7,150)
//
//        after dedicated window tables:
//
//        test bench_pedersen_hash ... bench:      37,373 ns/iter (+/- 2,020)
//
// -------------------------------------------------------------------------------------------------
//
//        My dev machine:
//        Total time per hash (nanos): 864,246
//
//        Neither MM nor lookups nor any other optimizations are implemented
//        so looks like there is plenty of room for improvement yet its good enough at least for experimentation


        val start = System.nanoTime()
        val numRuns = 1000
        for(m in 1..numRuns) {
            PedersenHash().hash(BitArray(m.toBigInteger().toByteArray()))
        }
        val finish = System.nanoTime()
        println("Total time (nanos): ${finish - start}")
        println("Total time per hash (nanos): ${(finish - start) / numRuns}")
    }
}