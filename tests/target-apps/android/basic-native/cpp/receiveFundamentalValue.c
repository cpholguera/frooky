#include <jni.h>
#include <stdio.h>
#include <stdbool.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT __attribute__((visibility("default")))

/* ---------- receive by value ---------- */
NOINLINE EXPORT bool receive_bool(bool minValue, bool maxValue) { return minValue; }
NOINLINE EXPORT char receive_char(char minValue, char maxValue) { return minValue; }
NOINLINE EXPORT signed char receive_schar(signed char minValue, signed char maxValue) { return minValue; }
NOINLINE EXPORT unsigned char receive_uchar(unsigned char minValue, unsigned char maxValue) { return minValue; }
NOINLINE EXPORT short receive_short(short minValue, short maxValue) { return minValue; }
NOINLINE EXPORT unsigned short receive_ushort(unsigned short minValue, unsigned short maxValue) { return minValue; }
NOINLINE EXPORT int receive_int(int minValue, int maxValue) { return minValue; }
NOINLINE EXPORT unsigned int receive_uint(unsigned int minValue, unsigned int maxValue) { return minValue; }
NOINLINE EXPORT long receive_long(long minValue, long maxValue) { return minValue; }
NOINLINE EXPORT unsigned long receive_ulong(unsigned long minValue, unsigned long maxValue) { return minValue; }
NOINLINE EXPORT long long receive_llong(long long minValue, long long maxValue) { return minValue; }
NOINLINE EXPORT unsigned long long receive_ullong(unsigned long long minValue, unsigned long long maxValue) { return minValue; }
NOINLINE EXPORT float receive_float(float minValue, float maxValue) { return minValue; }
NOINLINE EXPORT double receive_double(double minValue, double maxValue) { return minValue; }
NOINLINE EXPORT long double receive_ldouble(long double minValue, long double maxValue) { return minValue; }

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_receiveFundamentalValueJNI(JNIEnv *env, jobject thiz)
{
    (void)thiz;

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

    return (*env)->NewStringUTF(env, "Called functions with primitives received by value (e.g. void receive_int(int minValue, int maxValue)).");
}
