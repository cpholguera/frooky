#include <jni.h>
#include <stdio.h>
#include <stdbool.h>
#include <wchar.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT   __attribute__((visibility("default")))

/* ---------- pass by value ---------- */
NOINLINE EXPORT bool               pass_bool(bool v)                 { printf("bool: %d\n", v);       return v; }
NOINLINE EXPORT char               pass_char(char v)                 { printf("char: %c\n", v);       return v; }
NOINLINE EXPORT signed char        pass_schar(signed char v)         { printf("schar: %d\n", v);      return v; }
NOINLINE EXPORT unsigned char      pass_uchar(unsigned char v)       { printf("uchar: %u\n", v);      return v; }
NOINLINE EXPORT short              pass_short(short v)               { printf("short: %d\n", v);      return v; }
NOINLINE EXPORT unsigned short     pass_ushort(unsigned short v)     { printf("ushort: %u\n", v);     return v; }
NOINLINE EXPORT int                pass_int(int v)                   { printf("int: %d\n", v);        return v; }
NOINLINE EXPORT unsigned int       pass_uint(unsigned int v)         { printf("uint: %u\n", v);       return v; }
NOINLINE EXPORT long               pass_long(long v)                 { printf("long: %ld\n", v);      return v; }
NOINLINE EXPORT unsigned long      pass_ulong(unsigned long v)       { printf("ulong: %lu\n", v);     return v; }
NOINLINE EXPORT long long          pass_llong(long long v)           { printf("llong: %lld\n", v);    return v; }
NOINLINE EXPORT unsigned long long pass_ullong(unsigned long long v) { printf("ullong: %llu\n", v);   return v; }
NOINLINE EXPORT float              pass_float(float v)               { printf("float: %f\n", v);      return v; }
NOINLINE EXPORT double             pass_double(double v)             { printf("double: %f\n", v);     return v; }
NOINLINE EXPORT long double        pass_ldouble(long double v)       { printf("ldouble: %Lf\n", v);   return v; }
NOINLINE EXPORT wchar_t            pass_wchar(wchar_t v)             { printf("wchar: %d\n", (int)v); return v; }

/* ---------- pass by reference ---------- */
NOINLINE EXPORT void pass_bool_ref   (bool *p)               { printf("*bool: %d\n",    *p);       *p = !(*p); }
NOINLINE EXPORT void pass_char_ref   (char *p)               { printf("*char: %c\n",    *p);       *p += 1; }
NOINLINE EXPORT void pass_schar_ref  (signed char *p)        { printf("*schar: %d\n",   *p);       *p = -*p; }
NOINLINE EXPORT void pass_uchar_ref  (unsigned char *p)      { printf("*uchar: %u\n",   *p);       *p += 1; }
NOINLINE EXPORT void pass_short_ref  (short *p)              { printf("*short: %d\n",   *p);       *p = -*p; }
NOINLINE EXPORT void pass_ushort_ref (unsigned short *p)     { printf("*ushort: %u\n",  *p);       *p += 1; }
NOINLINE EXPORT void pass_int_ref    (int *p)                { printf("*int: %d\n",     *p);       *p = -*p; }
NOINLINE EXPORT void pass_uint_ref   (unsigned int *p)       { printf("*uint: %u\n",    *p);       *p += 1; }
NOINLINE EXPORT void pass_long_ref   (long *p)               { printf("*long: %ld\n",   *p);       *p = -*p; }
NOINLINE EXPORT void pass_ulong_ref  (unsigned long *p)      { printf("*ulong: %lu\n",  *p);       *p += 1; }
NOINLINE EXPORT void pass_llong_ref  (long long *p)          { printf("*llong: %lld\n", *p);       *p = -*p; }
NOINLINE EXPORT void pass_ullong_ref (unsigned long long *p) { printf("*ullong: %llu\n",*p);       *p += 1; }
NOINLINE EXPORT void pass_float_ref  (float *p)              { printf("*float: %f\n",   *p);       *p = -*p; }
NOINLINE EXPORT void pass_double_ref (double *p)             { printf("*double: %f\n",  *p);       *p = -*p; }
NOINLINE EXPORT void pass_ldouble_ref(long double *p)        { printf("*ldouble: %Lf\n",*p);       *p = -*p; }
NOINLINE EXPORT void pass_wchar_ref  (wchar_t *p)            { printf("*wchar: %d\n",  (int)*p);   *p += 1; }

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_passPrimitivesJNI(JNIEnv *env, jobject thiz) {
    (void)thiz;

    /* by value */
    pass_bool(true);
    pass_char('A');
    pass_schar(-5);
    pass_uchar(250);
    pass_short(-1234);
    pass_ushort(1234);
    pass_int(-42);
    pass_uint(42u);
    pass_long(-100000L);
    pass_ulong(100000UL);
    pass_llong(-1234567890123LL);
    pass_ullong(1234567890123ULL);
    pass_float(3.14f);
    pass_double(2.718281828);
    pass_ldouble(1.4142135623730951L);
    pass_wchar(L'Z');

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

    pass_bool_ref(&b);
    pass_char_ref(&c);
    pass_schar_ref(&sc);
    pass_uchar_ref(&uc);
    pass_short_ref(&s);
    pass_ushort_ref(&us);
    pass_int_ref(&i);
    pass_uint_ref(&ui);
    pass_long_ref(&l);
    pass_ulong_ref(&ul);
    pass_llong_ref(&ll);
    pass_ullong_ref(&ull);
    pass_float_ref(&f);
    pass_double_ref(&d);
    pass_ldouble_ref(&ld);
    pass_wchar_ref(&wc);

    return (*env)->NewStringUTF(env, "Called functions with primitives (by value and by reference).");
}
