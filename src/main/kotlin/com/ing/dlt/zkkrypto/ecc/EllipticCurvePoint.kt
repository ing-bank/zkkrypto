package com.ing.dlt.zkkrypto.ecc

import java.math.BigInteger

interface EllipticCurvePoint {
    val x: BigInteger
    val y: BigInteger
    val curve: EllipticCurve
    fun add(other: EllipticCurvePoint): EllipticCurvePoint
    fun scalarMult(scalar: BigInteger): EllipticCurvePoint
    fun double(): EllipticCurvePoint
    fun isOnCurve(): Boolean
}