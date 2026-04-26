package org.owasp.mastestapp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigDecimal
import java.math.BigInteger
import java.security.KeyPairGenerator

class MastgTest(private val context: Context) {
    fun initRsaKeyPair(): String {
        val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")

        // Define what the key can be used for and how
        val spec =
                KeyGenParameterSpec.Builder(
                                "TestKeyPair",
                                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                        )
                        .setKeySize(2048)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .build()

        keyPairGenerator.initialize(spec)

        return "Initialized RAS Key Pair with Spec: ${spec.toString()}"
    }

    fun buildIntentWithFlags(): String {
        val securityFlags =
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                        Intent.FLAG_GRANT_PREFIX_URI_PERMISSION or
                        Intent.FLAG_ACTIVITY_NEW_TASK or
                        Intent.FLAG_ACTIVITY_CLEAR_TASK

        Intent(Intent.ACTION_VIEW, Uri.EMPTY).apply {
            setPackage("org.owasp.mastestapp")
            setFlags(securityFlags)
        }
        return "Intent with various flags sent. Binary masked integer is: $securityFlags"
    }

    // Single types
    fun receiveString(arg: String) {}
    fun receiveBoolean(arg: Boolean) {}
    fun receiveByte(arg: Byte) {}
    fun receiveShort(arg: Short) {}
    fun receiveInt(arg: Int) {}
    fun receiveLong(arg: Long) {}
    fun receiveFloat(arg: Float) {}
    fun receiveDouble(arg: Double) {}
    fun receiveChar(arg: Char) {}

    fun receiveBigInteger(arg: BigInteger) {}
    fun receiveBigDecimal(arg: BigDecimal) {}
    fun receiveList(arg: List<String>) {}
    fun receiveMap(arg: Map<String, String>) {}
    fun receiveSet(arg: Set<String>) {}

    enum class Direction {
        NORTH,
        SOUTH,
        EAST,
        WEST
    }
    fun receiveEnum(arg: Direction) {}

    // Arrays
    fun receiveStringArray(arg: Array<String>) {}
    fun receiveBooleanArray(arg: BooleanArray) {}
    fun receiveByteArray(arg: ByteArray) {}
    fun receiveShortArray(arg: ShortArray) {}
    fun receiveIntArray(arg: IntArray) {}
    fun receiveLongArray(arg: LongArray) {}
    fun receiveFloatArray(arg: FloatArray) {}
    fun receiveDoubleArray(arg: DoubleArray) {}
    fun receiveCharArray(arg: CharArray) {}
    fun receiveNestedArray(arg: Array<Array<Array<String>>>) {} // nested array with depth of 3

    fun mastgTest(): String {
        val r = DemoResults("basic-parameter")

        receiveString("Test String")
        r.add(Status.PASS, "Test String")

        receiveBoolean(true)
        r.add(Status.PASS, true.toString())

        receiveByte(127)
        r.add(Status.PASS, 127.toString())

        receiveShort(32767)
        r.add(Status.PASS, 32767.toString())

        receiveInt(2147483647)
        r.add(Status.PASS, 2147483647.toString())

        receiveLong(9223372036854775807L)
        r.add(Status.PASS, 9223372036854775807L.toString())

        receiveFloat(3.14f)
        r.add(Status.PASS, 3.14f.toString())

        receiveDouble(3.141592653589793)
        r.add(Status.PASS, 3.141592653589793.toString())

        receiveChar('A')
        r.add(Status.PASS, 'A'.toString())

        val stringArray = arrayOf("a", "b", "c")
        receiveStringArray(stringArray)
        r.add(Status.PASS, stringArray.joinToString())

        val boolArray = booleanArrayOf(true, false)
        receiveBooleanArray(boolArray)
        r.add(Status.PASS, boolArray.joinToString())

        val byteArray = byteArrayOf(1, 2, 3)
        receiveByteArray(byteArray)
        r.add(Status.PASS, byteArray.joinToString())

        val shortArray = shortArrayOf(1, 2, 3)
        receiveShortArray(shortArray)
        r.add(Status.PASS, shortArray.joinToString())

        val intArray = intArrayOf(1, 2, 3)
        receiveIntArray(intArray)
        r.add(Status.PASS, intArray.joinToString())

        val longArray = longArrayOf(1L, 2L, 3L)
        receiveLongArray(longArray)
        r.add(Status.PASS, longArray.joinToString())

        val floatArray = floatArrayOf(1.1f, 2.2f)
        receiveFloatArray(floatArray)
        r.add(Status.PASS, floatArray.joinToString())

        val doubleArray = doubleArrayOf(1.1, 2.2)
        receiveDoubleArray(doubleArray)
        r.add(Status.PASS, doubleArray.joinToString())

        val charArray = charArrayOf('x', 'y', 'z')
        receiveCharArray(charArray)
        r.add(Status.PASS, charArray.joinToString())

        val bigInt = BigInteger("123456789012345678901234567890")
        receiveBigInteger(bigInt)
        r.add(Status.PASS, bigInt.toString())

        val bigDec = BigDecimal("3.141592653589793238462643383")
        receiveBigDecimal(bigDec)
        r.add(Status.PASS, bigDec.toString())

        val list = listOf("a", "b", "c")
        receiveList(list)
        r.add(Status.PASS, list.toString())

        val map = mapOf("key" to "value")
        receiveMap(map)
        r.add(Status.PASS, map.toString())

        val set = setOf("a", "b", "c")
        receiveSet(set)
        r.add(Status.PASS, set.toString())

        val nested =
                arrayOf(
                        arrayOf(arrayOf("a", "b", "c"), arrayOf("d", "e", "f")),
                        arrayOf(arrayOf("g", "h", "i"), arrayOf("j", "k", "l"))
                )

        receiveNestedArray(nested)
        r.add(Status.PASS, nested.toString())

        val longIntegerArray = Array(100) { it + 1 }.toIntArray()
        receiveIntArray(longIntegerArray)
        r.add(Status.PASS, longIntegerArray.toString())

        receiveEnum(Direction.NORTH)
        r.add(Status.PASS, Direction.NORTH.toString())

        r.add(Status.PASS, this.buildIntentWithFlags())

        r.add(Status.PASS, initRsaKeyPair())

        return r.toJson()
    }
}
