package com.ing.dlt.zkkrypto.ecc

interface ZKHash {

    /**
     * Hash size in bytes
     */
    val hashLength: Int

    fun hash(msg: ByteArray): ByteArray
}