package com.ing.dlt.zkkrypto.ecc.poseidon

import org.junit.jupiter.api.Test
import java.math.BigInteger

class PoseidonHashTest {

    @Test
    fun testConstantsGeneration() {
        PoseidonHash( r = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10))
    }

    @Test
    fun testReferenceImplementationCompatibility() {
        PoseidonHash( r = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10))
    }

    @Test
    fun testIden3Compatibility() {
        PoseidonHash( r = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10))
    }

    @Test
    fun testArnaucubeCompatibility() {
        PoseidonHash( r = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10))
    }
}