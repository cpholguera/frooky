package org.owasp.mastestapp

import android.content.Context

class MastgTest(private val context: Context) {

    companion object {
        init {
            System.loadLibrary("receiveFundamentalValue")
            System.loadLibrary("receiveFundamentalReference")
            System.loadLibrary("receiveString")
        }
    }

    external fun receiveFundamentalValueJNI(): String
    external fun receiveFundamentalReferenceJNI(): String
    external fun receiveStringsJNI(): String

    fun mastgTest(): String {
        val r = DemoResults("basic-native")
        r.add(Status.PASS, "${receiveFundamentalValueJNI()}")
        r.add(Status.PASS, "${receiveFundamentalReferenceJNI()}")
        r.add(Status.PASS, "${receiveStringsJNI()}")

        return r.toJson()
    }
}
