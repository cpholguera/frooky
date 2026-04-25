#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

void pass_cstring(const char *s)
{
    printf("cstring: %s\n", s);
}

void pass_utf8(const char *s)
{
    printf("utf8: %s\n", s);
}

void pass_utf16(const wchar_t *s)
{
    wprintf(L"utf16: %ls\n", s);
}

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_passStringsJNI(JNIEnv *env, jobject thiz)
{

    // NUL-terminated variants
    receive_cstring("Hello, CString!");
    receive_utf8("Hello, UTF-8! \xc3\xa9\xc3\xa0\xc3\xbc"); // éàü
    receive_utf16(L"Hello, UTF-16! \u00e9\u00e0\u00fc");    // éàü

    // Fixed-size variants (pass a buffer with known size)
    const char *sized = "SizedString\x00hidden";
    receive_cstring(sized); // reads only up to NUL

    return (*env)->NewStringUTF(env, "Called functions with primitives (by value and by reference).");
}
