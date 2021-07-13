package com.ing.dlt.zkkrypto.ecc.arithmetic

import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import com.ing.dlt.zkkrypto.ecc.curves.TwistedEdwardsCurve
import com.ing.dlt.zkkrypto.util.sqrtMod
import java.math.BigInteger

object TwistedEdwardsArithmetic {

    fun add(a: EllipticCurvePoint, b: EllipticCurvePoint): EllipticCurvePoint {

        require(a.curve is TwistedEdwardsCurve) { "Elliptic curve must be Twisted Edwards Curve" }
        require(a.curve == b.curve) { "Points should be on the same curve, A's curve is ${a.curve}, B's curve is ${b.curve}" }

//        x = (pointA.x * pointB.y + pointA.y * pointB.x) / (1 + d * pointA.x * pointB.x * pointA.y * pointB.y)
//        y = (pointA.y * pointB.y - a * pointA.x * pointB.x) / (1 - d * pointA.x * pointB.x * pointA.y * pointB.y)

        val curve = a.curve

        val xNomTerm1 = a.x.multiply(b.y).mod(curve.R)
        val xNomTerm2 = a.y.multiply(b.x).mod(curve.R)
        val xNom = xNomTerm1.add(xNomTerm2)

        val yNomTerm1 = a.y.multiply(b.y).mod(curve.R)
        val yNomTerm2 = a.x.multiply(b.x).mod(curve.R).multiply(curve.a).mod(curve.R)
        val yNom = yNomTerm1.subtract(yNomTerm2)

        val denomCommonTerm = curve.d.multiply(a.x).mod(curve.R).multiply(a.y).mod(curve.R).multiply(b.x).mod(curve.R).multiply(b.y).mod(curve.R)

        val xDenomInversed = BigInteger.ONE.add(denomCommonTerm).modInverse(curve.R)
        val yDenomInversed = BigInteger.ONE.subtract(denomCommonTerm).modInverse(curve.R)

        val resultX = xNom.multiply(xDenomInversed).mod(curve.R)
        val resultY = yNom.multiply(yDenomInversed).mod(curve.R)

        return EllipticCurvePoint(resultX, resultY, curve)
    }

    fun scalarMult(p: EllipticCurvePoint, scalar: BigInteger): EllipticCurvePoint {

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

    fun double(p: EllipticCurvePoint): EllipticCurvePoint {
        return p.add(p)
    }

    fun isOnCurve(p: EllipticCurvePoint): Boolean {

        require(p.curve is TwistedEdwardsCurve) { "Elliptic curve must be Twisted Edwards Curve" }

        // a * x^2 + y^2 = 1 + d * x^2 * y^2
        val d = p.curve.d

        val x2 = p.x.multiply(p.x).mod(p.curve.R)
        val ax2 = x2.multiply(p.curve.a).mod(p.curve.R)
        val y2 = p.y.multiply(p.y).mod(p.curve.R)

        val dTimesX2Y2 = d.multiply(x2).multiply(y2).mod(p.curve.R)

        return y2.add(ax2).mod(p.curve.R) == BigInteger.ONE.add(dTimesX2Y2).mod(p.curve.R)
    }

    fun getForY(y: BigInteger, sign: Boolean, curve: EllipticCurve): EllipticCurvePoint? {

        require(curve is TwistedEdwardsCurve) { "Elliptic curve must be Twisted Edwards Curve" }

        if (y >= curve.R) return null

        // HERE it' different from jubjub
        // Given a y on the curve, x^2 = (y^2 - 1) / (dy^2 - a)
        // This is defined for all valid y-coordinates,
        // as dy^2 - a = 0 has no solution in Fr.

        val y2 = (y * y) % curve.R

        // (y^2 - 1)
        val numerator = y2 - BigInteger.ONE

        // (dy^2 - a)
        val denominator = (y2 * curve.d - curve.a) % curve.R

        val invDenominator = denominator.modInverse(curve.R)

        // (y^2 - 1) / (dy^2 - a)
        val right = (numerator * invDenominator) % curve.R

        var x = right.sqrtMod(curve.FrGenerator, curve.R) ?: return null

        if ((x.toByteArray().last() % 2 != 0) != sign) {
            x = curve.R - x
        }
        val point = EllipticCurvePoint(x, y, curve)

        return if (point.isOnCurve()) point else null
    }
}