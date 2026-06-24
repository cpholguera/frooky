#include <stdlib.h>
#include <string.h>
#include <jni.h>

const char *receive_cstring(const char *s) { return s; }

const char *receive_utf8(const char *s) { return s; }

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_receiveStringsJNI(JNIEnv *env, jobject thiz)
{
    receive_cstring("Welcome the first OWASP MASCon, CString!");
    receive_utf8("Welcome the first OWASP MASCon 📱❤️");

    return (*env)->NewStringUTF(env, "Called functions which receive C-Sting, UTF-8-String and UTF-16-String.");
}
