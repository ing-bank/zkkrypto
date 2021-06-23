package com.ing.dlt.zkkrypto.ecc.curves

import com.ing.dlt.zkkrypto.ecc.arithmetic.TwistedEdwardsArithmetic
import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

/**
 * Simple curve that uses solely Twisted Edwards form arithmetics
 */
interface TwistedEdwardsCurve : EllipticCurve {

    val a: BigInteger
    val d: BigInteger

    override fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint = TwistedEdwardsArithmetic.add(a, b)

    override fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint = TwistedEdwardsArithmetic.scalarMult(p, scalar)

    override fun double(p: EllipticCurvePoint): EllipticCurvePoint = TwistedEdwardsArithmetic.double(p)

    override fun isOnCurve(p: EllipticCurvePoint): Boolean  = TwistedEdwardsArithmetic.isOnCurve(p)

    override fun getForY(y: BigInteger, sign: Boolean): EllipticCurvePoint? = TwistedEdwardsArithmetic.getForY(y, sign, this)
}