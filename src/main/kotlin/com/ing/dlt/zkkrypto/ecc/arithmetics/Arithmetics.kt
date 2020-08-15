package com.ing.dlt.zkkrypto.ecc.arithmetics

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

interface Arithmetics {
    fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint
    fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint
    fun double(p: EllipticCurvePoint): EllipticCurvePoint
    fun isOnCurve(p: EllipticCurvePoint): Boolean
}