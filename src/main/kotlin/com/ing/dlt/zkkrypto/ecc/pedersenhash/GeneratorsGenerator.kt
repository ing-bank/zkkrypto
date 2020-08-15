package com.ing.dlt.zkkrypto.ecc.pedersenhash

import com.ing.dlt.zkkrypto.ecc.EllipticCurvePoint
import com.ing.dlt.zkkrypto.ecc.EllipticCurve
import com.ing.dlt.zkkrypto.ecc.curves.AltBabyJubjub
import com.ing.dlt.zkkrypto.ecc.curves.BabyJubjub
import com.ing.dlt.zkkrypto.ecc.curves.Jubjub
import java.math.BigInteger

/**
 * Now all the generators are hardcoded,
 * need to add generation of generators in GeneratorsGenerator so we can generate generators
 */
object GeneratorsGenerator {

    /**
     * Constants from librustzcash test
     * They don't have it hardcoded but for now its easier to get them from runtime comparing to reimplementing group hash
     */
    fun zcashLibrust(): List<EllipticCurvePoint> {

        return listOf(
            EllipticCurvePoint(
                BigInteger("73c016a42ded9578b5ea25de7ec0e3782f0c718f6f0fbadd194e42926f661b51", 16),
                BigInteger("289e87a2d3521b5779c9166b837edc5ef9472e8bc04e463277bfabd432243cca", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("15a36d1f0f390d8852a35a8c1908dd87a361ee3fd48fdf77b9819dc82d90607e", 16),
                BigInteger("015d8c7f5b43fe33f7891142c001d9251f3abeeb98fad3e87b0dc53c4ebf1891", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("664321a58246e2f6eb69ae39f5c84210bae8e5c46641ae5c76d6f7c2b67fc475", 16),
                BigInteger("362e1500d24eee9ee000a46c8e8ce8538bb22a7f1784b49880ed502c9793d457", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("323a6548ce9d9876edc5f4a9cff29fd57d02d50e654b87f24c767804c1c4a2cc", 16),
                BigInteger("2f7ee40c4b56cad891070acbd8d947b75103afa1a11f6a8584714beca33570e9", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("3bd2666000b5479689b64b4e03362796efd5931305f2f0bf46809430657f82d1", 16),
                BigInteger("494bc52103ab9d0a397832381406c9e5b3b9d8095859d14c99968299c3658aef", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("63447b2ba31bb28ada049746d76d3ee51d9e5ca21135ff6fcb3c023258d32079", 16),
                BigInteger("64ec4689e8bfb6e564cdb1070a136a28a80200d2c66b13a7436082119f8d629a", 16),
                Jubjub
            )
        )
    }

    /**
     * Generators from Zinc
     */
    fun zincAltBabyJubjub(): List<EllipticCurvePoint> {
        return listOf(
            EllipticCurvePoint(
                BigInteger("184570ed4909a81b2793320a26e8f956be129e4eed381acf901718dff8802135", 16),
                BigInteger("1c3a9a830f61587101ef8cbbebf55063c1c6480e7e5a7441eac7f626d8f69a45", 16),
                AltBabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("0afc00ffa0065f5479f53575e86f6dcd0d88d7331eefd39df037eea2d6f031e4", 16),
                BigInteger("237a6734dd50e044b4f44027ee9e70fcd2e5724ded1d1c12b820a11afdc15c7a", 16),
                AltBabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("00fb62ad05ee0e615f935c5a83a870f389a5ea2baccf22ad731a4929e7a75b37", 16),
                BigInteger("00bc8b1c9d376ceeea2cf66a91b7e2ad20ab8cce38575ac13dbefe2be548f702", 16),
                AltBabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("0675544aa0a708b0c584833fdedda8d89be14c516e0a7ef3042f378cb01f6e48", 16),
                BigInteger("169025a530508ee4f1d34b73b4d32e008b97da2147f15af3c53f405cf44f89d4", 16),
                AltBabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("07350a0660a05014168047155c0a0647ea2720ecb182a6cb137b29f8a5cfd37f", 16),
                BigInteger("3004ad73b7abe27f17ec04b04b450955a4189dd012b4cf4b174af15bd412696a", 16),
                AltBabyJubjub
            )
        )
    }

    /**
     * Generators from Zinc
     */
    fun zincBabyJubjub(): List<EllipticCurvePoint> {
        return listOf(
            EllipticCurvePoint(
                BigInteger("", 16),
                BigInteger("", 16),
                BabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("", 16),
                BigInteger("", 16),
                BabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("", 16),
                BigInteger("", 16),
                BabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("", 16),
                BigInteger("", 16),
                BabyJubjub
            ),
            EllipticCurvePoint(
                BigInteger("", 16),
                BigInteger("", 16),
                BabyJubjub
            )
        )
    }

    /**
     * Constants from
     * https://github.com/matter-labs/pedersen_hash_standard
     */
    fun zcashBlakePrecomputed(): List<EllipticCurvePoint> {

        return listOf(
            EllipticCurvePoint(
                BigInteger("184570ed4909a81b2793320a26e8f956be129e4eed381acf901718dff8802135", 16),
                BigInteger("1c3a9a830f61587101ef8cbbebf55063c1c6480e7e5a7441eac7f626d8f69a45", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("0afc00ffa0065f5479f53575e86f6dcd0d88d7331eefd39df037eea2d6f031e4", 16),
                BigInteger("237a6734dd50e044b4f44027ee9e70fcd2e5724ded1d1c12b820a11afdc15c7a", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("00fb62ad05ee0e615f935c5a83a870f389a5ea2baccf22ad731a4929e7a75b37", 16),
                BigInteger("00bc8b1c9d376ceeea2cf66a91b7e2ad20ab8cce38575ac13dbefe2be548f702", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("0675544aa0a708b0c584833fdedda8d89be14c516e0a7ef3042f378cb01f6e48", 16),
                BigInteger("169025a530508ee4f1d34b73b4d32e008b97da2147f15af3c53f405cf44f89d4", 16),
                Jubjub
            ),
            EllipticCurvePoint(
                BigInteger("07350a0660a05014168047155c0a0647ea2720ecb182a6cb137b29f8a5cfd37f", 16),
                BigInteger("3004ad73b7abe27f17ec04b04b450955a4189dd012b4cf4b174af15bd412696a", 16),
                Jubjub
            )
        )
    }

    fun defaultForCurve(curve: EllipticCurve): List<EllipticCurvePoint> {
        return when (curve) {
            is Jubjub -> zcashLibrust()
            is BabyJubjub -> zincBabyJubjub()
            is AltBabyJubjub -> zincAltBabyJubjub()
            else -> throw IllegalArgumentException("Unknown curve: $curve")
        }
    }
}