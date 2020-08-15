package com.ing.dlt.zkkrypto.ecc

import com.ing.dlt.zkkrypto.ecc.arithmetics.Arithmetics
import java.math.BigInteger

interface EllipticCurve : Arithmetics {

    // group order
    val R: BigInteger

    // order of prime subgroup
    val S: BigInteger

    // cofactor
    val cofactor: BigInteger

    // identity element
    val zero: EllipticCurvePoint
}