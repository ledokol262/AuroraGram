add_library(integrity STATIC
        integrity/integrity.cpp
        integrity/meth.cpp
        integrity/openat.c
        integrity/read_cert.cpp
        integrity/SHA1.cpp)
target_compile_options(integrity PUBLIC
        -Oz -Wall -fvisibility=hidden)
target_include_directories(integrity PUBLIC
        integrity)

# AuroraGram uses its own APK signing certificate instead of the original Nagram signer.
# Keep the APK path/ownership checks, but do not reject the fork's signature in JNI_OnLoad.
target_compile_definitions(integrity PRIVATE AURORAGRAM_ALLOW_CUSTOM_SIGNATURE=1)
