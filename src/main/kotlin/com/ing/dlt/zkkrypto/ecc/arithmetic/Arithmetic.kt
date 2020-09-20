package com.ing.dlt.zkkrypto.ecc.arithmetic

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

interface Arithmetic {
    fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint
    fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint
    fun double(p: EllipticCurvePoint): EllipticCurvePoint
    fun isOnCurve(p: EllipticCurvePoint): Boolean
}