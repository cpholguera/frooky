#include <jni.h>
#include <stdio.h>
#include <stdbool.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT   __attribute__((visibility("default")))

/* ---------- pass by value ---------- */
NOINLINE EXPORT void pass_bool   (bool minValue,               bool maxValue)               { }
NOINLINE EXPORT void pass_char   (char minValue,               char maxValue)               { }
NOINLINE EXPORT void pass_schar  (signed char minValue,        signed char maxValue)        { }
NOINLINE EXPORT void pass_uchar  (unsigned char minValue,      unsigned char maxValue)      { }
NOINLINE EXPORT void pass_short  (short minValue,              short maxValue)              { }
NOINLINE EXPORT void pass_ushort (unsigned short minValue,     unsigned short maxValue)     { }
NOINLINE EXPORT void pass_int    (int minValue,                int maxValue)                { }
NOINLINE EXPORT void pass_uint   (unsigned int minValue,       unsigned int maxValue)       { }
NOINLINE EXPORT void pass_long   (long minValue,               long maxValue)               { }
NOINLINE EXPORT void pass_ulong  (unsigned long minValue,      unsigned long maxValue)      { }
NOINLINE EXPORT void pass_llong  (long long minValue,          long long maxValue)          { }
NOINLINE EXPORT void pass_ullong (unsigned long long minValue, unsigned long long maxValue) { }
NOINLINE EXPORT void pass_float  (float minValue,              float maxValue)              { }
NOINLINE EXPORT void pass_double (double minValue,             double maxValue)             { }
NOINLINE EXPORT void pass_ldouble(long double minValue,        long double maxValue)        { }

/* ---------- pass by reference ---------- */
NOINLINE EXPORT void pass_bool_ref   (bool *minValue,               bool *maxValue)               { }
NOINLINE EXPORT void pass_char_ref   (char *minValue,               char *maxValue)               { }
NOINLINE EXPORT void pass_schar_ref  (signed char *minValue,        signed char *maxValue)        { }
NOINLINE EXPORT void pass_uchar_ref  (unsigned char *minValue,      unsigned char *maxValue)      { }
NOINLINE EXPORT void pass_short_ref  (short *minValue,              short *maxValue)              { }
NOINLINE EXPORT void pass_ushort_ref (unsigned short *minValue,     unsigned short *maxValue)     { }
NOINLINE EXPORT void pass_int_ref    (int *minValue,                int *maxValue)                { }
NOINLINE EXPORT void pass_uint_ref   (unsigned int *minValue,       unsigned int *maxValue)       { }
NOINLINE EXPORT void pass_long_ref   (long *minValue,               long *maxValue)               { }
NOINLINE EXPORT void pass_ulong_ref  (unsigned long *minValue,      unsigned long *maxValue)      { }
NOINLINE EXPORT void pass_llong_ref  (long long *minValue,          long long *maxValue)          { }
NOINLINE EXPORT void pass_ullong_ref (unsigned long long *minValue, unsigned long long *maxValue) { }
NOINLINE EXPORT void pass_float_ref  (float *minValue,              float *maxValue)              { }
NOINLINE EXPORT void pass_double_ref (double *minValue,             double *maxValue)             { }
NOINLINE EXPORT void pass_ldouble_ref(long double *minValue,        long double *maxValue)        { }

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_passPrimitivesJNI(JNIEnv *env, jobject thiz) {
    (void)thiz;

    /* by value */
    pass_bool   (false,                   true);
    pass_char   ('A',                     'Z');
    pass_schar  (-128,                    127);
    pass_uchar  (0,                       255);
    pass_short  (-32768,                  32767);
    pass_ushort (0,                       65535);
    pass_int    (-2147483648,             2147483647);
    pass_uint   (0u,                      4294967295u);
    pass_long   (-2147483648L,            2147483647L);
    pass_ulong  (0UL,                     4294967295UL);
    pass_llong  (-9223372036854775807LL,  9223372036854775807LL);
    pass_ullong (0ULL,                    18446744073709551615ULL);
    pass_float  (-3.4028235e38f,          3.4028235e38f);
    pass_double (-1.7976931348623157e308, 1.7976931348623157e308);
    pass_ldouble(-1.18973149535723176e4932L, 1.18973149535723176e4932L);

    /* by reference */
    bool               minBool = false,  maxBool = true;
    char               minChar = 'A',    maxChar = 'Z';
    signed char        minSc   = -128,   maxSc   = 127;
    unsigned char      minUc   = 0,      maxUc   = 255;
    short              minS    = -32768, maxS    = 32767;
    unsigned short     minUs   = 0,      maxUs   = 65535;
    int                minI    = -2147483648,             maxI   = 2147483647;
    unsigned int       minUi   = 0u,                      maxUi  = 4294967295u;
    long               minL    = -2147483648L,            maxL   = 2147483647L;
    unsigned long      minUl   = 0UL,                     maxUl  = 4294967295UL;
    long long          minLl   = -9223372036854775807LL,  maxLl  = 9223372036854775807LL;
    unsigned long long minUll  = 0ULL,                    maxUll = 18446744073709551615ULL;
    float              minF    = -3.4028235e38f,          maxF   = 3.4028235e38f;
    double             minD    = -1.7976931348623157e308, maxD   = 1.7976931348623157e308;
    long double        minLd   = -1.18973149535723176e4932L, maxLd = 1.18973149535723176e4932L;

    pass_bool_ref   (&minBool, &maxBool);
    pass_char_ref   (&minChar, &maxChar);
    pass_schar_ref  (&minSc,   &maxSc);
    pass_uchar_ref  (&minUc,   &maxUc);
    pass_short_ref  (&minS,    &maxS);
    pass_ushort_ref (&minUs,   &maxUs);
    pass_int_ref    (&minI,    &maxI);
    pass_uint_ref   (&minUi,   &maxUi);
    pass_long_ref   (&minL,    &maxL);
    pass_ulong_ref  (&minUl,   &maxUl);
    pass_llong_ref  (&minLl,   &maxLl);
    pass_ullong_ref (&minUll,  &maxUll);
    pass_float_ref  (&minF,    &maxF);
    pass_double_ref (&minD,    &maxD);
    pass_ldouble_ref(&minLd,   &maxLd);

    return (*env)->NewStringUTF(env, "Called functions with primitives (by value and by reference).");
}
