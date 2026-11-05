/* SPDX-License-Identifier: MIT
 * JNI bridge: expose the native detectors (from ../../native) to Kotlin so the
 * decisive checks live in a .so, not in easily-patched smali.
 * Build with the NDK, linking the ars_shield static lib. */
#include <jni.h>
#include "shield.h"   /* from native/include */

JNIEXPORT jint JNICALL
Java_shield_NativeBridge_scan(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jint)ars_scan();
}

JNIEXPORT jlong JNICALL
Java_shield_NativeBridge_textHash(JNIEnv *env, jobject thiz) {
    (void)env; (void)thiz;
    return (jlong)ars_text_hash();
}
