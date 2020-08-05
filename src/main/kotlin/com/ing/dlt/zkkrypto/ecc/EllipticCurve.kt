package com.ing.dlt.zkkrypto.ecc

import java.math.BigInteger

interface EllipticCurve {

    // group order
    val R: BigInteger

    // order of prime subgroup
    val S: BigInteger

    // d parameter
    val d: BigInteger

    // cofactor
    val cofactor: BigInteger

    // identity element
    val zero: EllipticCurvePoint
}