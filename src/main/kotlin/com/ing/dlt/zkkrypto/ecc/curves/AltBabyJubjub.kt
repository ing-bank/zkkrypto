package com.ing.dlt.zkkrypto.ecc.curves

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

object AltBabyJubjub : EdwardsCurve {

    override val R = BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
    override val S = BigInteger("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)
    // d = -(168696/168700)
    override val d = BigInteger("12181644023421730124874158521699555681764249180949974110617291017600649128846", 10)
    override val cofactor: BigInteger = BigInteger.valueOf(8)

    override val zero: EllipticCurvePoint = EllipticCurvePoint(BigInteger.ZERO, BigInteger.ONE, this)
}