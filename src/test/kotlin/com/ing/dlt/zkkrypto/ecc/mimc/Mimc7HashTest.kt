package com.ing.dlt.zkkrypto.ecc.mimc

import org.bouncycastle.jcajce.provider.digest.Keccak
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 * Tested to be compatible with Mimc-rs (https://github.com/arnaucube/mimc-rs) and, transitively, with Iden3 (https://github.com/iden3/go-iden3-crypto)
 */
class Mimc7HashTest {

    @Test
    fun testKeccak() {

        val sha3: Keccak.Digest256 = Keccak.Digest256()

        val seedHash = sha3.digest(Mimc7Hash.defaultSeed)

        assertEquals(
        Hex.toHexString(seedHash),
        "b6e489e6b37224a50bebfddbe7d89fa8fdcaa84304a70bd13f79b5d9f7951e9e"
        )
    }

    @Test
    fun testConstantsGeneration() {

        val constants = Mimc7Hash.generateRoundConstants(
            r = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
        )
        assertEquals(
            "20888961410941983456478427210666206549300505294776164667214940546594746570981",
            constants[1].toString(10)
        )
    }
    
    @Test 
    fun testBigIntegerHashing() {

        val b12 = BigInteger("12", 10)
        val b45 = BigInteger("45", 10)
        val b78 = BigInteger("78", 10)
        val b41 = BigInteger("41", 10)

        val mimc7 = Mimc7Hash(BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10))
        
        val ints1 = listOf(b12)
        val h1 = mimc7.hash(ints1)
        assertEquals(
            Hex.toHexString(h1),
        "237c92644dbddb86d8a259e0e923aaab65a93f1ec5758b8799988894ac0958fd"
        )

        val ints2 = listOf(b78, b41)
        val h2 = mimc7.hash(ints2)
        assertEquals(
            Hex.toHexString(h2),
        "067f3202335ea256ae6e6aadcd2d5f7f4b06a00b2d1e0de903980d5ab552dc70"
        )

        val ints3 = listOf(b12, b45)
        val h3 = mimc7.hash(ints3)
        assertEquals(
            Hex.toHexString(h3),
        "15ff7fe9793346a17c3150804bcb36d161c8662b110c50f55ccb7113948d8879"
        )

        val ints4 = listOf(b12, b45, b78, b41)
        val h4 = mimc7.hash(ints4)
        assertEquals(
            Hex.toHexString(h4),
        "284bc1f34f335933a23a433b6ff3ee179d682cd5e5e2fcdd2d964afa85104beb"
        )
    }

    @Test
    fun testBytesHashing() {

        val msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

        val mimc7 = Mimc7Hash(BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10))

        val h = mimc7.hash(msg.toByteArray())
        assertEquals(
            BigInteger(h).toString(10),
        "16855787120419064316734350414336285711017110414939748784029922801367685456065"
        )

    }
}