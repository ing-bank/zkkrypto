package com.ing.dlt.zkkrypto.ecc

import java.math.BigInteger

data class EllipticCurvePoint(val x: BigInteger, val y: BigInteger, val curve: EllipticCurve) {

    fun add(other: EllipticCurvePoint): EllipticCurvePoint = curve.add(this, other)
    fun scalarMult(scalar: BigInteger): EllipticCurvePoint = curve.scalarMult(this, scalar)
    fun double(): EllipticCurvePoint = curve.double(this)
    fun isOnCurve(): Boolean = curve.isOnCurve(this)
}
