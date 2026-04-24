#include <jni.h>
#include <stdio.h>
#include <stdbool.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT   __attribute__((visibility("default")))

/* ---------- pass by value ---------- */
NOINLINE EXPORT bool               pass_bool   (bool minValue,               bool maxValue)               { return minValue; }
NOINLINE EXPORT char               pass_char   (char minValue,               char maxValue)               { return minValue; }
NOINLINE EXPORT signed char        pass_schar  (signed char minValue,        signed char maxValue)        { return minValue; }
NOINLINE EXPORT unsigned char      pass_uchar  (unsigned char minValue,      unsigned char maxValue)      { return minValue; }
NOINLINE EXPORT short              pass_short  (short minValue,              short maxValue)              { return minValue; }
NOINLINE EXPORT unsigned short     pass_ushort (unsigned short minValue,     unsigned short maxValue)     { return minValue; }
NOINLINE EXPORT int                pass_int    (int minValue,                int maxValue)                { return minValue; }
NOINLINE EXPORT unsigned int       pass_uint   (unsigned int minValue,       unsigned int maxValue)       { return minValue; }
NOINLINE EXPORT long               pass_long   (long minValue,               long maxValue)               { return minValue; }
NOINLINE EXPORT unsigned long      pass_ulong  (unsigned long minValue,      unsigned long maxValue)      { return minValue; }
NOINLINE EXPORT long long          pass_llong  (long long minValue,          long long maxValue)          { return minValue; }
NOINLINE EXPORT unsigned long long pass_ullong (unsigned long long minValue, unsigned long long maxValue) { return minValue; }
NOINLINE EXPORT float              pass_float  (float minValue,              float maxValue)              { return minValue; }
NOINLINE EXPORT double             pass_double (double minValue,             double maxValue)             { return minValue; }
NOINLINE EXPORT long double        pass_ldouble(long double minValue,        long double maxValue)        { return minValue; }

/* ---------- pass by reference ---------- */
NOINLINE EXPORT void pass_bool_ref   (bool *p,               bool minValue,               bool maxValue)               { *p = !(*p); }
NOINLINE EXPORT void pass_char_ref   (char *p,               char minValue,               char maxValue)               { *p += 1; }
NOINLINE EXPORT void pass_schar_ref  (signed char *p,        signed char minValue,        signed char maxValue)        { *p = -*p; }
NOINLINE EXPORT void pass_uchar_ref  (unsigned char *p,      unsigned char minValue,      unsigned char maxValue)      { *p += 1; }
NOINLINE EXPORT void pass_short_ref  (short *p,              short minValue,              short maxValue)              { *p = -*p; }
NOINLINE EXPORT void pass_ushort_ref (unsigned short *p,     unsigned short minValue,     unsigned short maxValue)     { *p += 1; }
NOINLINE EXPORT void pass_int_ref    (int *p,                int minValue,                int maxValue)                { *p = -*p; }
NOINLINE EXPORT void pass_uint_ref   (unsigned int *p,       unsigned int minValue,       unsigned int maxValue)       { *p += 1; }
NOINLINE EXPORT void pass_long_ref   (long *p,               long minValue,               long maxValue)               { *p = -*p; }
NOINLINE EXPORT void pass_ulong_ref  (unsigned long *p,      unsigned long minValue,      unsigned long maxValue)      { *p += 1; }
NOINLINE EXPORT void pass_llong_ref  (long long *p,          long long minValue,          long long maxValue)          { *p = -*p; }
NOINLINE EXPORT void pass_ullong_ref (unsigned long long *p, unsigned long long minValue, unsigned long long maxValue) { *p += 1; }
NOINLINE EXPORT void pass_float_ref  (float *p,              float minValue,              float maxValue)              { *p = -*p; }
NOINLINE EXPORT void pass_double_ref (double *p,             double minValue,             double maxValue)             { *p = -*p; }
NOINLINE EXPORT void pass_ldouble_ref(long double *p,        long double minValue,        long double maxValue)        { *p = -*p; }

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
    bool               b   = true;
    char               c   = 'A';
    signed char        sc  = -5;
    unsigned char      uc  = 250;
    short              s   = -1234;
    unsigned short     us  = 1234;
    int                i   = -42;
    unsigned int       ui  = 42u;
    long               l   = -100000L;
    unsigned long      ul  = 100000UL;
    long long          ll  = -1234567890123LL;
    unsigned long long ull = 1234567890123ULL;
    float              f   = 3.14f;
    double             d   = 2.718281828;
    long double        ld  = 1.4142135623730951L;
    wchar_t            wc  = L'Z';

    pass_bool_ref   (&b,   false,                    true);
    pass_char_ref   (&c,   'A',                      'Z');
    pass_schar_ref  (&sc,  -128,                     127);
    pass_uchar_ref  (&uc,  0,                        255);
    pass_short_ref  (&s,   -32768,                   32767);
    pass_ushort_ref (&us,  0,                        65535);
    pass_int_ref    (&i,   -2147483648,               2147483647);
    pass_uint_ref   (&ui,  0u,                        4294967295u);
    pass_long_ref   (&l,   -2147483648L,              2147483647L);
    pass_ulong_ref  (&ul,  0UL,                       4294967295UL);
    pass_llong_ref  (&ll,  -9223372036854775807LL,    9223372036854775807LL);
    pass_ullong_ref (&ull, 0ULL,                      18446744073709551615ULL);
    pass_float_ref  (&f,   -3.4028235e38f,            3.4028235e38f);
    pass_double_ref (&d,   -1.7976931348623157e308,   1.7976931348623157e308);
    pass_ldouble_ref(&ld,  -1.18973149535723176e4932L, 1.18973149535723176e4932L);

    return (*env)->NewStringUTF(env, "Called functions with primitives (by value and by reference).");
}
