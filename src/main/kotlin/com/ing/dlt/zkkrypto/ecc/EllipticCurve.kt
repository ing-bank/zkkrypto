package com.ing.dlt.zkkrypto.ecc

import com.ing.dlt.zkkrypto.ecc.arithmetic.Arithmetic
import java.math.BigInteger

interface EllipticCurve : Arithmetic {

    // group order
    val R: BigInteger

    // order of prime subgroup
    val S: BigInteger

    // cofactor
    val cofactor: BigInteger

    // identity element
    val zero: EllipticCurvePoint
}