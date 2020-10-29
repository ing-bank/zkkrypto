package com.ing.dlt.zkkrypto.ecc.schnorr

import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import com.ing.dlt.zkkrypto.ecc.pedersenhash.GeneratorsGenerator
import java.math.BigInteger

object FixedGenerators {
    /**
     * Base points to be used in different protocols. Right now we only use SpendingKeyGenerator for Schnorr signatures
     */
    fun altBabyJubjubFixedGenerators(): List<EllipticCurvePoint> {
        return listOf(
            //ProofGenerationKey
            EllipticCurvePoint(
                BigInteger("1ee77350e12c9895b2ce939094e92af260b4a56c9a4f09230e0ff0c5786a30ca", 16),
                BigInteger("18c6409592649c36a79a15177b4aec5784075f5a03f9a1b09a57af4b288f929d", 16),
                AltBabyJubjub
            ),
            //NoteCommitmentRandomness
            EllipticCurvePoint(
                BigInteger("1f8151972518489ee4e4877f27a98ee98b16045a3df8a623f782090b4592bcee", 16),
                BigInteger("2590f9fbe09f7f5e83a29e97bb97981a6125edb96af6577c738af072bf1142e4", 16),
                AltBabyJubjub
            ),
            //NullifierPosition
            EllipticCurvePoint(
                BigInteger("06365233b672101388d5d99a9514a8ba26ccbbae043205293d8aa2b1254dda88", 16),
                BigInteger("063007fe32cc0f6934b24bfc11bdaaf82cdaab270e596c1a1cac59ab9d85ab81", 16),
                AltBabyJubjub
            ),
            //ValueCommitmentValue
            EllipticCurvePoint(
                BigInteger("0a71462a426047520559654bf211850d5060582816d27c4a80dd05c85112b2ad", 16),
                BigInteger("0042358566d0cd4c9cfa3b48b85b5b7653cd483fa71222b378a6952ab6232e5f", 16),
                AltBabyJubjub
            ),
            //ValueCommitmentRandomness
            EllipticCurvePoint(
                BigInteger("21108e5b084a15ced07f197a5e7ae8b7c52076fdb63c5b9b245ba5e2711b8abc", 16),
                BigInteger("0c4ea6f36b841e28a3bea6b126ac247e7f0558d717b6d5c4734063cd762a5099", 16),
                AltBabyJubjub
            ),
            //SpendingKeyGenerator
            EllipticCurvePoint(
                BigInteger("2ef3f9b423a2c8c74e9803958f6c320e854a1c1c06cd5cc8fd221dc052d76df7", 16),
                BigInteger("05a01167ea785d3f784224644a68e4067532c815f5f6d57d984b5c0e9c6c94b7", 16),
                AltBabyJubjub
            )
        )
    }

}