package com.ing.dlt.zkkrypto.ecc.poseidon

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger

/**
 * Tested to be compatible with Iden3 implementation
 */
class PoseidonHashTest {

    @Test
    fun testHashing() {
        val poseidon = PoseidonHash()

        val b0 = BigInteger.valueOf(0)
        val b1 = BigInteger.valueOf(1)
        val b2 = BigInteger.valueOf(2)
        val b3 = BigInteger.valueOf(3)
        val b4 = BigInteger.valueOf(4)
        val b5 = BigInteger.valueOf(5)
        val b6 = BigInteger.valueOf(6)

        var h = poseidon.hash(listOf(b1))
        
        assertEquals("11043376183861534927536506085090418075369306574649619885724436265926427398571", h.toString(10))

        h = poseidon.hash(listOf(b1, b2))
        
        assertEquals("17117985411748610629288516079940078114952304104811071254131751175361957805920", h.toString(10))

        h = poseidon.hash(listOf(b1, b2, b0, b0, b0))
        
        assertEquals("3975478831357328722254985704342968745327876719981393787143845259590563829094", h.toString(10))
        h = poseidon.hash(listOf(b1, b2, b0, b0, b0, b0))
        
        assertEquals("19772360636270345724087386688434825760738403416279047262510528378903625000110", h.toString(10))


        h = poseidon.hash(listOf(b3, b4, b0, b0, b0))
        
        assertEquals("3181200837746671699652342497997860344148947482942465819251904554707352676086", h.toString(10))
        h = poseidon.hash(listOf(b3, b4, b0, b0, b0, b0))
        
        assertEquals("8386348873272147968934270337233829407378789978142456170950021426339096575008", h.toString(10))


        h = poseidon.hash(listOf(b1, b2, b3, b4, b5, b6))
        
        assertEquals("5202465217520500374834597824465244016759843635092906214933648999760272616044", h.toString(10))
    }
}