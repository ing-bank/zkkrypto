package com.ing.dlt.zkkrypto.ecc.curves

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

object Jubjub : EdwardsCurve {

    override val R = BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
    override val S = BigInteger("e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7", 16)
    // d = -(10240/10241)
    override val d = BigInteger("2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1", 16)
    override val cofactor: BigInteger = BigInteger.valueOf(8)

    override val zero: EllipticCurvePoint = EllipticCurvePoint(BigInteger.ZERO, BigInteger.ONE, this)
}