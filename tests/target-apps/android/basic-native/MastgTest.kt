package org.owasp.mastestapp

import android.content.Context

class MastgTest(private val context: Context) {

    static {
        System.loadLibrary("native-lib");
    }

    fun mastgTest(): String {
        val r = DemoResults("basic-native")f


        r.add(Status.PASS, "Loaded native library and ran various functions.")


        return r.toJson()
    }
}