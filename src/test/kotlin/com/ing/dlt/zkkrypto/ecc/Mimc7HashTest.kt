package com.ing.dlt.zkkrypto.ecc

import com.ing.dlt.zkkrypto.ecc.mimc.Mimc7Hash
import org.bouncycastle.jcajce.provider.digest.Keccak
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 *
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
    fun test_generate_constants() {

        val constants = Mimc7Hash.generateRoundConstants(
            r = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
        )
        assertEquals(
            "20888961410941983456478427210666206549300505294776164667214940546594746570981",
            constants[1].toString(10)
        )
    }
}