package com.ing.dlt.zkkrypto.ecc.pedersenhash

import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import com.ing.dlt.zkkrypto.ecc.curves.Jubjub
import com.ing.dlt.zkkrypto.util.BitArray
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.random.Random

internal class PedersenHashTest {

    @Test
    fun jubjub() {

        TestVectors.jubjub.forEach { vector ->

            val hash  = BigInteger(PedersenHash.zcash().hash(vector.input_bits))

            assertEquals(BigInteger(vector.hash_x, 16), hash)
        }
    }

    @Test
    fun altBabyJubjubStrings() {

        TestVectors.altBabyJubjub.forEach { vector ->

            val hash = BigInteger(PedersenHash(curve = AltBabyJubjub, chunksPerGenerator = 62)
                .hash(vector.input_bits))

            assertEquals(BigInteger(vector.hash_x, 16), hash)
        }
    }

    @Test
    fun altBabyJubjubBytes() {

        TestVectors.altBabyJubjubBytes.forEach { vector ->

            val hash = BigInteger(PedersenHash.zinc.hash(vector.input_bits))

            assertEquals(vector.hash_x,  hash.toString(16))
        }
    }

    @Test
    fun zincDefaultTest() {

        val vector = TestVectors.TestVector(
            personalization = TestVectors.Personalization.NoteCommitment,
            input_bits = BitArray.fromString("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010"),
            hash_x = "d799568a2faaebce79310bbb84e454bf934e61f1879c8095ac7c0a45905d2d3",
            hash_y = "40d2992106b2c6e8c2f0b38e5238fbd9b46ef042d91011a5566044f2943ac65"
        )

        val hash  = BigInteger(PedersenHash.zinc.hash(vector.input_bits))

        assertEquals(vector.hash_x, hash.toString(16))
    }

    @Test
    fun zincGeneratorsTest() {

        val hardcoded = Generators.zincAltBabyJubjub().iterator()

        val calculated = PedersenHash.zinc.generators.iterator()

        for (i in 0..4) {
            val h = hardcoded.next()
            val c = calculated.next()
            require(h == c) { "Generated generators should be equal to pregenerated generators" }
        }

        for (i in 0..2) {
            require(calculated.iterator().hasNext())
            val next = calculated.iterator().next() // shouldn't fail
            require(next.isOnCurve())
        }
    }

    @Test
    fun constantSizeHash() {

//        PH(40) = 00116fbd117d117768ec0f977d857df3e278015d4ce9fd4d08bd6c153ebd1fa2
//        48058 hashes to the point where X coordinate is only 31 byte long
//        so we check it was correctly padded with zero byte at zero position to be 32-bytes constant size

        val m = 40
        val hash = PedersenHash.zcash().hash(BitArray(m.toBigInteger().toByteArray()))
        assertEquals(0, hash[0])
        assertEquals(32, hash.size)
        assertEquals("116fbd117d117768ec0f977d857df3e278015d4ce9fd4d08bd6c153ebd1fa2", BigInteger(hash).toString(16))
    }


    @Test
    fun salt() {

        val full = Random.Default.nextBytes(ByteArray(10))

        val expected = PedersenHash.zcash().hash(full)

        val msg = full.drop(4).toByteArray()
        val salt = full.dropLast(full.size - 4).toByteArray()

        val hash = PedersenHash(curve = Jubjub).hash(msg, BitArray(salt))

        assertArrayEquals(expected, hash)
    }


//    @Test
    fun hashSingle() {

        val len = 1
        val ph = PedersenHash.zinc
        val f42 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010"
        val msg = BitArray.fromString(f42 + f42 + f42 + f42 + f42)
        val hash = ph.hash(msg)
        println(BigInteger(hash).toString(16))
    }

//    @Test
    fun benchmarkGenerators() {

//        Total time (nanos): 16.701.578.307 ~ 16 seconds
//        Total time per generator (nanos): 521.924 ~ 0.5 milliseconds
//
//        Will do for now but its clear how to optimize it further


        val calculated = PedersenHash.zinc.generators.iterator()

        val start = System.nanoTime()
        val numRuns = 4 * 8 * 1000 // ~ 1 MB
        for(i in 0..numRuns) {
            calculated.next()
        }
        val finish = System.nanoTime()
        println("Total time (nanos): ${finish - start}")
        println("Average time per generator (nanos): ${(finish - start) / numRuns}")
    }

//    @Test
    fun benchmarkLongHash() {

        val ph = PedersenHash.zinc

        // Generate generators
        val calculated = ph.generators.iterator()

        var start = System.nanoTime()
        var numRuns = 4 * 8 * 1000 // ~ 1 MB
        for(i in 0..numRuns) {
            calculated.next()
        }
        var finish = System.nanoTime()
        println("Total time (nanos): ${finish - start}")
        println("Average time per generator (nanos): ${(finish - start) / numRuns}")


        // Hash
        val msg = Random.nextBytes(1000000)

        start = System.nanoTime()
        numRuns = 1
        for(i in 0..numRuns) {
            ph.hash(msg)
        }
        finish = System.nanoTime()
        println("Average time per hash (nanos): ${(finish - start) / numRuns}")
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
            PedersenHash(curve = Jubjub).hash(BitArray(m.toBigInteger().toByteArray()))
        }
        val finish = System.nanoTime()
        println("Total time (nanos): ${finish - start}")
        println("Average time per hash (nanos): ${(finish - start) / numRuns}")
    }
}