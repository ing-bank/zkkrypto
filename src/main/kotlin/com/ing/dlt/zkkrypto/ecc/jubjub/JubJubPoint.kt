package com.ing.dlt.zkkrypto.ecc.jubjub

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.lang.IllegalStateException
import java.math.BigInteger

data class JubJubPoint(override val x: BigInteger, override val y: BigInteger, override val curve: JubJub = JubJub.default) :
    EllipticCurvePoint {

    init {
        if (!isOnCurve()) throw IllegalStateException("Point is not on the curve")
    }

    override fun add(other: EllipticCurvePoint): EllipticCurvePoint {

//        x = (this.x * other.y + this.y * other.x) / (1 + d * this.x * other.x * this.y * other.y)
//        y = (this.y * other.y + this.x * other.x) / (1 - d * this.x * other.x * this.y * other.y)

        val xNomTerm1 = this.x.multiply(other.y).mod(curve.R)
        val xNomTerm2 = this.y.multiply(other.x).mod(curve.R)
        val xNom = xNomTerm1.add(xNomTerm2)

        val yNomTerm1 = this.y.multiply(other.y).mod(curve.R)
        val yNomTerm2 = this.x.multiply(other.x).mod(curve.R)
        val yNom = yNomTerm1.add(yNomTerm2)

        val denomCommonTerm = curve.d.multiply(x).mod(curve.R).multiply(y).mod(curve.R).multiply(other.x).mod(curve.R).multiply(other.y).mod(curve.R)

        val xDenomInversed = BigInteger.ONE.add(denomCommonTerm).modInverse(curve.R)
        val yDenomInversed = BigInteger.ONE.subtract(denomCommonTerm).modInverse(curve.R)

        val resultX = xNom.multiply(xDenomInversed).mod(curve.R)
        val resultY = yNom.multiply(yDenomInversed).mod(curve.R)

        return JubJubPoint(resultX, resultY, curve)
    }

    override fun scalarMult(scalar: BigInteger): EllipticCurvePoint {

        // double & add

        val s = scalar.mod(curve.R)
        var doubling: EllipticCurvePoint = this.copy()
        var result: EllipticCurvePoint = curve.zero

        for( i in 0 until s.bitLength() ) {
            if (s.testBit(i)) {
                result = result.add(doubling)
            }
            doubling = doubling.double()
        }
        return result
    }

    override fun double(): EllipticCurvePoint {
        return this.add(this)
    }

    override fun isOnCurve(): Boolean {

        // -x^2 + y^2 = 1 + d * x^2 * y^2

        val x2 = x.multiply(x).mod(curve.R)
        val y2 = y.multiply(y).mod(curve.R)

        val dTimesX2Y2 = curve.d.multiply(x2).multiply(y2).mod(curve.R)

        return y2.subtract(x2).mod(curve.R) == BigInteger.ONE.add(dTimesX2Y2).mod(curve.R)
    }
}