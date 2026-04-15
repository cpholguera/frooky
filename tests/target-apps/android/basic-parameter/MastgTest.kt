package org.owasp.mastestapp

import java.math.BigDecimal
import java.math.BigInteger

import android.content.Context

class MastgTest(private val context: Context) {

    // Single types
    fun passString(arg: String): String = arg
    fun passBoolean(arg: Boolean): Boolean = arg
    fun passByte(arg: Byte): Byte = arg
    fun passShort(arg: Short): Short = arg
    fun passInt(arg: Int): Int = arg
    fun passLong(arg: Long): Long = arg
    fun passFloat(arg: Float): Float = arg
    fun passDouble(arg: Double): Double = arg
    fun passChar(arg: Char): Char = arg


    fun passBigInteger(arg: BigInteger): BigInteger = arg
    fun passBigDecimal(arg: BigDecimal): BigDecimal = arg
    fun passList(arg: List<String>): List<String> = arg
    fun passMap(arg: Map<String, String>): Map<String, String> = arg
    fun passSet(arg: Set<String>): Set<String> = arg

    enum class Direction { NORTH, SOUTH, EAST, WEST }
    fun passEnum(arg: Direction): Direction = arg
    
    // Arrays
    fun passStringArray(arg: Array<String>): Array<String> = arg
    fun passBooleanArray(arg: BooleanArray): BooleanArray = arg
    fun passByteArray(arg: ByteArray): ByteArray = arg
    fun passShortArray(arg: ShortArray): ShortArray = arg
    fun passIntArray(arg: IntArray): IntArray = arg
    fun passLongArray(arg: LongArray): LongArray = arg
    fun passFloatArray(arg: FloatArray): FloatArray = arg
    fun passDoubleArray(arg: DoubleArray): DoubleArray = arg
    fun passCharArray(arg: CharArray): CharArray = arg

    fun mastgTest(): String {
        val r = DemoResults("basic-parameter")

        r.add(Status.PASS, passString("Test String"))
        r.add(Status.PASS, passBoolean(true).toString())
        r.add(Status.PASS, passByte(127).toString())
        r.add(Status.PASS, passShort(32767).toString())
        r.add(Status.PASS, passInt(2147483647).toString())
        r.add(Status.PASS, passLong(9223372036854775807L).toString())
        r.add(Status.PASS, passFloat(3.14f).toString())
        r.add(Status.PASS, passDouble(3.141592653589793).toString())
        r.add(Status.PASS, passChar('A').toString())

        r.add(Status.PASS, passStringArray(arrayOf("a", "b", "c")).joinToString())
        r.add(Status.PASS, passBooleanArray(booleanArrayOf(true, false)).joinToString())
        r.add(Status.PASS, passByteArray(byteArrayOf(1, 2, 3)).joinToString())
        r.add(Status.PASS, passShortArray(shortArrayOf(1, 2, 3)).joinToString())
        r.add(Status.PASS, passIntArray(intArrayOf(1, 2, 3)).joinToString())
        r.add(Status.PASS, passLongArray(longArrayOf(1L, 2L, 3L)).joinToString())
        r.add(Status.PASS, passFloatArray(floatArrayOf(1.1f, 2.2f)).joinToString())
        r.add(Status.PASS, passDoubleArray(doubleArrayOf(1.1, 2.2)).joinToString())
        r.add(Status.PASS, passCharArray(charArrayOf('x', 'y', 'z')).joinToString())



        r.add(Status.PASS, passBigInteger(BigInteger("123456789012345678901234567890")).toString())
        r.add(Status.PASS, passBigDecimal(BigDecimal("3.141592653589793238462643383")).toString())
        r.add(Status.PASS, passList(listOf("a", "b", "c")).toString())
        r.add(Status.PASS, passMap(mapOf("key" to "value")).toString())
        r.add(Status.PASS, passSet(setOf("a", "b", "c")).toString())
        r.add(Status.PASS, passEnum(Direction.NORTH).toString())

        return r.toJson()
    }
}
