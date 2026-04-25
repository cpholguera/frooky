#include <jni.h>
#include <stdio.h>
#include <stdbool.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT __attribute__((visibility("default")))

/* ---------- receive by value ---------- */
NOINLINE EXPORT void receive_bool(bool minValue, bool maxValue) {}
NOINLINE EXPORT void receive_char(char minValue, char maxValue) {}
NOINLINE EXPORT void receive_schar(signed char minValue, signed char maxValue) {}
NOINLINE EXPORT void receive_uchar(unsigned char minValue, unsigned char maxValue) {}
NOINLINE EXPORT void receive_short(short minValue, short maxValue) {}
NOINLINE EXPORT void receive_ushort(unsigned short minValue, unsigned short maxValue) {}
NOINLINE EXPORT void receive_int(int minValue, int maxValue) {}
NOINLINE EXPORT void receive_uint(unsigned int minValue, unsigned int maxValue) {}
NOINLINE EXPORT void receive_long(long minValue, long maxValue) {}
NOINLINE EXPORT void receive_ulong(unsigned long minValue, unsigned long maxValue) {}
NOINLINE EXPORT void receive_llong(long long minValue, long long maxValue) {}
NOINLINE EXPORT void receive_ullong(unsigned long long minValue, unsigned long long maxValue) {}
NOINLINE EXPORT void receive_float(float minValue, float maxValue) {}
NOINLINE EXPORT void receive_double(double minValue, double maxValue) {}
NOINLINE EXPORT void receive_ldouble(long double minValue, long double maxValue) {}

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_receiveFundamentalValueJNI(JNIEnv *env, jobject thiz)
{
    (void)thiz;

    /* by value */
    receive_bool(false, true);
    receive_char('A', 'Z');
    receive_schar(-128, 127);
    receive_uchar(0, 255);
    receive_short(-32768, 32767);
    receive_ushort(0, 65535);
    receive_int(-2147483648, 2147483647);
    receive_uint(0u, 4294967295u);
    receive_long(-2147483648L, 2147483647L);
    receive_ulong(0UL, 4294967295UL);
    receive_llong(-9223372036854775807LL, 9223372036854775807LL);
    receive_ullong(0ULL, 18446744073709551615ULL);
    receive_float(-3.4028235e38f, 3.4028235e38f);
    receive_double(-1.7976931348623157e308, 1.7976931348623157e308);
    receive_ldouble(-1.18973149535723176e4932L, 1.18973149535723176e4932L);

    return (*env)->NewStringUTF(env, "Called functions with primitives received by value (e.g. void receive_bool(bool minValue, bool maxValue)).");
}
