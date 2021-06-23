package com.ing.dlt.zkkrypto.ecc

import java.math.BigInteger

interface EllipticCurve {

    // group order
    val R: BigInteger

    // group generator
    val FrGenerator: BigInteger

    // order of prime subgroup
    val S: BigInteger

    // cofactor
    val cofactor: BigInteger

    // identity element
    val zero: EllipticCurvePoint

    fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint
    fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint
    fun double(p: EllipticCurvePoint): EllipticCurvePoint
    fun isOnCurve(p: EllipticCurvePoint): Boolean
    fun getForY(y: BigInteger, sign: Boolean): EllipticCurvePoint?
}