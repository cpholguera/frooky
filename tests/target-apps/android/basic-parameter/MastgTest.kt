package org.owasp.mastestapp

import java.math.BigDecimal
import java.math.BigInteger

import android.content.Context

class MastgTest(private val context: Context) {

    // Single types
    fun passString(arg: String) {}
    fun passBoolean(arg: Boolean) {}
    fun passByte(arg: Byte) {}
    fun passShort(arg: Short) {}
    fun passInt(arg: Int) {}
    fun passLong(arg: Long) {}
    fun passFloat(arg: Float) {}
    fun passDouble(arg: Double) {}
    fun passChar(arg: Char) {}

    fun passBigInteger(arg: BigInteger) {}
    fun passBigDecimal(arg: BigDecimal) {}
    fun passList(arg: List<String>) {}
    fun passMap(arg: Map<String, String>) {}
    fun passSet(arg: Set<String>) {}

    enum class Direction { NORTH, SOUTH, EAST, WEST }
    fun passEnum(arg: Direction) {}

    // Arrays
    fun passStringArray(arg: Array<String>) {}
    fun passBooleanArray(arg: BooleanArray) {}
    fun passByteArray(arg: ByteArray) {}
    fun passShortArray(arg: ShortArray) {}
    fun passIntArray(arg: IntArray) {}
    fun passLongArray(arg: LongArray) {}
    fun passFloatArray(arg: FloatArray) {}
    fun passDoubleArray(arg: DoubleArray) {}
    fun passCharArray(arg: CharArray) {}

    fun mastgTest(): String {
        val r = DemoResults("basic-parameter")

        passString("Test String")
        r.add(Status.PASS, "Test String")

        passBoolean(true)
        r.add(Status.PASS, true.toString())

        passByte(127)
        r.add(Status.PASS, 127.toString())

        passShort(32767)
        r.add(Status.PASS, 32767.toString())

        passInt(2147483647)
        r.add(Status.PASS, 2147483647.toString())

        passLong(9223372036854775807L)
        r.add(Status.PASS, 9223372036854775807L.toString())

        passFloat(3.14f)
        r.add(Status.PASS, 3.14f.toString())

        passDouble(3.141592653589793)
        r.add(Status.PASS, 3.141592653589793.toString())

        passChar('A')
        r.add(Status.PASS, 'A'.toString())

        val stringArray = arrayOf("a", "b", "c")
        passStringArray(stringArray)
        r.add(Status.PASS, stringArray.joinToString())

        val boolArray = booleanArrayOf(true, false)
        passBooleanArray(boolArray)
        r.add(Status.PASS, boolArray.joinToString())

        val byteArray = byteArrayOf(1, 2, 3)
        passByteArray(byteArray)
        r.add(Status.PASS, byteArray.joinToString())

        val shortArray = shortArrayOf(1, 2, 3)
        passShortArray(shortArray)
        r.add(Status.PASS, shortArray.joinToString())

        val intArray = intArrayOf(1, 2, 3)
        passIntArray(intArray)
        r.add(Status.PASS, intArray.joinToString())

        val longArray = longArrayOf(1L, 2L, 3L)
        passLongArray(longArray)
        r.add(Status.PASS, longArray.joinToString())

        val floatArray = floatArrayOf(1.1f, 2.2f)
        passFloatArray(floatArray)
        r.add(Status.PASS, floatArray.joinToString())

        val doubleArray = doubleArrayOf(1.1, 2.2)
        passDoubleArray(doubleArray)
        r.add(Status.PASS, doubleArray.joinToString())

        val charArray = charArrayOf('x', 'y', 'z')
        passCharArray(charArray)
        r.add(Status.PASS, charArray.joinToString())

        val bigInt = BigInteger("123456789012345678901234567890")
        passBigInteger(bigInt)
        r.add(Status.PASS, bigInt.toString())

        val bigDec = BigDecimal("3.141592653589793238462643383")
        passBigDecimal(bigDec)
        r.add(Status.PASS, bigDec.toString())

        val list = listOf("a", "b", "c")
        passList(list)
        r.add(Status.PASS, list.toString())

        val map = mapOf("key" to "value")
        passMap(map)
        r.add(Status.PASS, map.toString())

        val set = setOf("a", "b", "c")
        passSet(set)
        r.add(Status.PASS, set.toString())

        passEnum(Direction.NORTH)
        r.add(Status.PASS, Direction.NORTH.toString())

        return r.toJson()
    }
}
