# R8 / ProGuard hardening. Enable in build.gradle:
#   release { minifyEnabled true; shrinkResources true }
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
-optimizationpasses 5

# Strip logging from release builds (removes string hints)
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Keep JNI entry points if you bridge to the native .so layer
-keepclasseswithmembernames class * { native <methods>; }
