package org.owasp.mastestapp

import android.content.Context

class MastgTest(private val context: Context) {

    companion object {
        init {
            System.loadLibrary("fundamentalTypes")
            System.loadLibrary("stringTypes")
        }
    }

    external fun passFundamentalValueJNI(): String
    external fun passStringTypesJNI(): String

    fun mastgTest(): String {
        val r = DemoResults("basic-native")
        r.add(
                Status.PASS,
                "Loaded native library and ran functions which receive fundamental types by value: ${passFundamentalValueJNI()}"
        )

        r.add(
                Status.PASS,
                "Loaded native library and ran various functions: ${passStringTypesJNI()}"
        )

        return r.toJson()
    }
}
