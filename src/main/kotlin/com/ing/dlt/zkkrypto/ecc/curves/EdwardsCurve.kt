package com.ing.dlt.zkkrypto.ecc.curves

import com.ing.dlt.zkkrypto.ecc.arithmetics.EdwardsForm
import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

/**
 * Simple curve that uses solely Edwards form arithmetics
 */
interface EdwardsCurve : EllipticCurve {

    // d parameter
    val d: BigInteger

    override fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint = EdwardsForm.add(a, b)

    override fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint = EdwardsForm.scalarMult(p, scalar)

    override fun double(p: EllipticCurvePoint): EllipticCurvePoint = EdwardsForm.double(p)

    override fun isOnCurve(p: EllipticCurvePoint): Boolean  = EdwardsForm.isOnCurve(p)
}