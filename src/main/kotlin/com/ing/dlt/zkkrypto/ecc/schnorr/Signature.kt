package com.ing.dlt.zkkrypto.ecc.schnorr

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import java.math.BigInteger

data class Signature(val r: EllipticCurvePoint, val s: BigInteger)
