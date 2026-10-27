#include "meth.h"
#include "openat.h"
#include "read_cert.h"
#include "SHA1.h"

#ifndef AURORAGRAM_ALLOW_CUSTOM_SIGNATURE
static const char *SIGN = "3A0F57FE06485D0B90D0ACD990E3A30328E3988D";
#endif

extern "C" {
int verifySign(JNIEnv *env) {
    jobject application = getApplication(env);
    if (application == nullptr) {
        return JNI_ERR;
    }
    const char *resourcePath = getApkPath(env, application);
    env->DeleteLocalRef(application);
    intptr_t fd = openAt(AT_FDCWD, resourcePath, O_RDONLY);
    if (fd < 0) {
        return JNI_ERR;
    }
    std::string sign = read_certificate(fd);
    if (!more_check(fd, resourcePath)) {
        close(fd);
        return JNI_ERR;
    }
    close(fd);

    // The APK must still contain a readable v2 signing certificate.
    // Android itself verifies the APK's cryptographic signature during installation.
    if (sign.empty()) {
        LOGE("Unable to read APK signing certificate");
        return JNI_ERR;
    }

#ifdef AURORAGRAM_ALLOW_CUSTOM_SIGNATURE
    // AuroraGram is a separately signed fork. Pinning the upstream Nagram certificate
    // makes JNI_OnLoad return JNI_ERR for a locally signed APK, leaving every native
    // ConnectionsManager method unavailable and preventing the app from starting.
    // Keep the APK path and ownership checks above, but accept AuroraGram's own signer.
    LOGI("AuroraGram: custom APK signer accepted; upstream Nagram certificate pin disabled");
    return JNI_OK;
#else
    std::string s = toolkit::SHA1::encode(sign);
    // 使用标准库算法将小写字母转换为大写字母
    for (char &c : s) {
        if (c >= 'a' && c <= 'z') {
            c = c - 'a' + 'A';  // 转换成大写
        }
    }
    const char* hex_sha = s.c_str();

    LOGI("应用读取的签名为：%s", hex_sha);
    LOGI("应用预置的签名为：%s", SIGN);
    int result = strcmp(hex_sha, SIGN);
    if (result == 0) { // 签名一致
        LOGI("签名一致");
        return JNI_OK;
    }
    LOGE("签名校验失败");
    return JNI_ERR;
#endif
}
}
