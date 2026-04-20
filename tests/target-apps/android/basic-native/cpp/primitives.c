#include <jni.h>
#include <stdio.h>
#include <stdbool.h>
#include <wchar.h>

#define NOINLINE __attribute__((noinline))
#define EXPORT   __attribute__((visibility("default")))

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

JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_passPrimitivesJNI(JNIEnv *env, jobject thiz) {
    (void)thiz; /* silence unused-parameter warning */

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

    return (*env)->NewStringUTF(env, "Called a functions with primitives.");
}
