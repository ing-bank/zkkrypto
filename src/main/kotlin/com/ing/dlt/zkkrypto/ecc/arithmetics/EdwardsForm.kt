package com.ing.dlt.zkkrypto.ecc.arithmetics

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import com.ing.dlt.zkkrypto.ecc.curves.EdwardsCurve
import java.lang.IllegalArgumentException
import java.math.BigInteger

object EdwardsForm : Arithmetics {

    override fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint {

//        x = (pointA.x * pointB.y + pointA.y * pointB.x) / (1 + d * pointA.x * pointB.x * pointA.y * pointB.y)
//        y = (pointA.y * pointB.y + pointA.x * pointB.x) / (1 - d * pointA.x * pointB.x * pointA.y * pointB.y)

        if(a.curve != b.curve) throw IllegalArgumentException("Points should be on the same curve, A's curve is ${a.curve}, B's curve is ${b.curve}")

        val curve = a.curve as EdwardsCurve

        val xNomTerm1 = a.x.multiply(b.y).mod(curve.R)
        val xNomTerm2 = a.y.multiply(b.x).mod(curve.R)
        val xNom = xNomTerm1.add(xNomTerm2)

        val yNomTerm1 = a.y.multiply(b.y).mod(curve.R)
        val yNomTerm2 = a.x.multiply(b.x).mod(curve.R)
        val yNom = yNomTerm1.add(yNomTerm2)

        val denomCommonTerm = curve.d.multiply(a.x).mod(curve.R).multiply(a.y).mod(curve.R).multiply(b.x).mod(curve.R).multiply(b.y).mod(curve.R)

        val xDenomInversed = BigInteger.ONE.add(denomCommonTerm).modInverse(curve.R)
        val yDenomInversed = BigInteger.ONE.subtract(denomCommonTerm).modInverse(curve.R)

        val resultX = xNom.multiply(xDenomInversed).mod(curve.R)
        val resultY = yNom.multiply(yDenomInversed).mod(curve.R)

        return EllipticCurvePoint(resultX, resultY, curve)
    }

    override fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint {

        // double & add

        val s = scalar.mod(p.curve.R)
        var doubling: EllipticCurvePoint = p.copy()
        var result: EllipticCurvePoint = p.curve.zero

        for( i in 0 until s.bitLength() ) {
            if (s.testBit(i)) {
                result = result.add(doubling)
            }
            doubling = doubling.double()
        }
        return result
    }

    override fun double(p: EllipticCurvePoint): EllipticCurvePoint {
        return p.add(p)
    }

    override fun isOnCurve(p: EllipticCurvePoint): Boolean {

        // -x^2 + y^2 = 1 + d * x^2 * y^2

        val d = (p.curve as EdwardsCurve).d

        val x2 = p.x.multiply(p.x).mod(p.curve.R)
        val y2 = p.y.multiply(p.y).mod(p.curve.R)

        val dTimesX2Y2 = d.multiply(x2).multiply(y2).mod(p.curve.R)

        return y2.subtract(x2).mod(p.curve.R) == BigInteger.ONE.add(dTimesX2Y2).mod(p.curve.R)
    }

}