#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_org_owasp_mastestapp_MastgTest_stringFromJNI(JNIEnv* env, jobject /* this */) {
    return env->NewStringUTF("Hello from C++");
}
