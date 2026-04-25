#include <stdlib.h>
#include <string.h>
#include <jni.h>

void receive_cstring(const char *s) {}

void receive_utf8(const char *s) {}

void receive_utf16(const wchar_t *s) {}

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_receiveStringsJNI(JNIEnv *env, jobject thiz)
{

    // NUL-terminated variants
    receive_cstring("Hello, CString!");
    receive_utf8("Hello, UTF-8! ❤️✅😭✨🫪🥹🔥✔️🫩");
    receive_utf16(L"Hello, UTF-16! ❤️✅😭✨🫪🥹🔥✔️🫩");

    return (*env)->NewStringUTF(env, "Called functions which receive C-Sting, UTF-8-String and UTF-16-String.");
}
