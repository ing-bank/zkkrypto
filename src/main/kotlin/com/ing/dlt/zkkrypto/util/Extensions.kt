package com.ing.dlt.zkkrypto.util

fun Byte.asUnsigned() = this.toInt() and 0xFF

/** Performs a bitwise AND operation between the two values. */
inline infix fun Byte.and(other: Byte): Byte = (this.toInt() and other.toInt()).toByte()

/** Performs a bitwise OR operation between the two values. */
inline infix fun Byte.or(other: Byte): Byte = (this.toInt() or other.toInt()).toByte()
