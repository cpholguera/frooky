#include <jni.h>
#include <stdio.h>
#include <stdbool.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT __attribute__((visibility("default")))

/* ---------- receive by reference ---------- */
NOINLINE EXPORT void receive_bool_ref(bool *minValue, bool *maxValue) {}
NOINLINE EXPORT void receive_char_ref(char *minValue, char *maxValue) {}
NOINLINE EXPORT void receive_schar_ref(signed char *minValue, signed char *maxValue) {}
NOINLINE EXPORT void receive_uchar_ref(unsigned char *minValue, unsigned char *maxValue) {}
NOINLINE EXPORT void receive_short_ref(short *minValue, short *maxValue) {}
NOINLINE EXPORT void receive_ushort_ref(unsigned short *minValue, unsigned short *maxValue) {}
NOINLINE EXPORT void receive_int_ref(int *minValue, int *maxValue) {}
NOINLINE EXPORT void receive_uint_ref(unsigned int *minValue, unsigned int *maxValue) {}
NOINLINE EXPORT void receive_long_ref(long *minValue, long *maxValue) {}
NOINLINE EXPORT void receive_ulong_ref(unsigned long *minValue, unsigned long *maxValue) {}
NOINLINE EXPORT void receive_llong_ref(long long *minValue, long long *maxValue) {}
NOINLINE EXPORT void receive_ullong_ref(unsigned long long *minValue, unsigned long long *maxValue) {}
NOINLINE EXPORT void receive_float_ref(float *minValue, float *maxValue) {}
NOINLINE EXPORT void receive_double_ref(double *minValue, double *maxValue) {}
NOINLINE EXPORT void receive_ldouble_ref(long double *minValue, long double *maxValue) {}
NOINLINE EXPORT void receive_byte_array(unsigned char *data, int length) {}

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_receiveFundamentalReferenceJNI(JNIEnv *env, jobject thiz)
{
    (void)thiz;

    bool minBool = false, maxBool = true;
    char minChar = 'A', maxChar = 'Z';
    signed char minSc = -128, maxSc = 127;
    unsigned char minUc = 0, maxUc = 255;
    short minS = -32768, maxS = 32767;
    unsigned short minUs = 0, maxUs = 65535;
    int minI = -2147483648, maxI = 2147483647;
    unsigned int minUi = 0u, maxUi = 4294967295u;
    long minL = -2147483648L, maxL = 2147483647L;
    unsigned long minUl = 0UL, maxUl = 4294967295UL;
    long long minLl = -9223372036854775807LL, maxLl = 9223372036854775807LL;
    unsigned long long minUll = 0ULL, maxUll = 18446744073709551615ULL;
    float minF = -3.4028235e38f, maxF = 3.4028235e38f;
    double minD = -1.7976931348623157e308, maxD = 1.7976931348623157e308;
    long double minLd = -1.18973149535723176e4932L, maxLd = 1.18973149535723176e4932L;
    unsigned char data[] = {0x00, 0x01, 0x02, 0xFF, 0xFE};

    receive_bool_ref(&minBool, &maxBool);
    receive_char_ref(&minChar, &maxChar);
    receive_schar_ref(&minSc, &maxSc);
    receive_uchar_ref(&minUc, &maxUc);
    receive_short_ref(&minS, &maxS);
    receive_ushort_ref(&minUs, &maxUs);
    receive_int_ref(&minI, &maxI);
    receive_uint_ref(&minUi, &maxUi);
    receive_long_ref(&minL, &maxL);
    receive_ulong_ref(&minUl, &maxUl);
    receive_llong_ref(&minLl, &maxLl);
    receive_ullong_ref(&minUll, &maxUll);
    receive_float_ref(&minF, &maxF);
    receive_double_ref(&minD, &maxD);
    receive_ldouble_ref(&minLd, &maxLd);
    receive_byte_array(data, 4);

    return (*env)->NewStringUTF(env, "Called functions with primitives received by reference (e.g. void receive_int(int *minValue, int *maxValue)).");
}
