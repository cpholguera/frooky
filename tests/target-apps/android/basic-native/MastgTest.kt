package org.owasp.mastestapp

import android.content.Context

class MastgTest(private val context: Context) {

    companion object {
        init {
            System.loadLibrary("primitives")
        }
    }

    external fun passPrimitivesJNI(): String

    fun mastgTest(): String {
        val r = DemoResults("basic-native")
        r.add(Status.PASS, "Loaded native library and ran various functions: ${passPrimitivesJNI()}")
        return r.toJson()
    }
}
