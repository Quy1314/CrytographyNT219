#include "RSAInterop.h"
#include "rsa_lib.h"
#include <jni.h>
#include <cstring>

extern "C" {

// ===== 1. GenerateKeyPair =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1GenerateKeyPair
  (JNIEnv* env, jobject, jint keySize, jstring privFile, jstring pubFile, jint usePEM)
{
    const char* priv = env->GetStringUTFChars(privFile, nullptr);
    const char* pub  = env->GetStringUTFChars(pubFile, nullptr);
    RSAStatusCode result = RSA_GenerateKeyPair((unsigned)keySize, priv, pub, usePEM);
    env->ReleaseStringUTFChars(privFile, priv);
    env->ReleaseStringUTFChars(pubFile, pub);
    return result;
}

// ===== 2. LoadPublicKey =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1LoadPublicKey
  (JNIEnv* env, jobject, jstring filename, jlongArray handleArr)
{
    const char* fname = env->GetStringUTFChars(filename, nullptr);
    RSAPublicKeyHandle key = nullptr;
    RSAStatusCode st = RSA_LoadPublicKey(fname, &key);
    env->ReleaseStringUTFChars(filename, fname);
    if (st == RSA_SUCCESS) {
        jlong ptr = reinterpret_cast<jlong>(key);
        env->SetLongArrayRegion(handleArr, 0, 1, &ptr);
    }
    return st;
}

// ===== 3. LoadPrivateKey =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1LoadPrivateKey
  (JNIEnv* env, jobject, jstring filename, jlongArray handleArr)
{
    const char* fname = env->GetStringUTFChars(filename, nullptr);
    RSAPrivateKeyHandle key = nullptr;
    RSAStatusCode st = RSA_LoadPrivateKey(fname, &key);
    env->ReleaseStringUTFChars(filename, fname);
    if (st == RSA_SUCCESS) {
        jlong ptr = reinterpret_cast<jlong>(key);
        env->SetLongArrayRegion(handleArr, 0, 1, &ptr);
    }
    return st;
}

// ===== 4. FreePublicKey =====
JNIEXPORT void JNICALL Java_RSAInterop_RSA_1FreePublicKey
  (JNIEnv*, jobject, jlong handle)
{
    RSA_FreePublicKey((RSAPublicKeyHandle)handle);
}

// ===== 5. FreePrivateKey =====
JNIEXPORT void JNICALL Java_RSAInterop_RSA_1FreePrivateKey
  (JNIEnv*, jobject, jlong handle)
{
    RSA_FreePrivateKey((RSAPrivateKeyHandle)handle);
}

// ===== 6. Encrypt =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1Encrypt
  (JNIEnv* env, jobject, jlong handle, jbyteArray data, jlong dataLen,
   jbyteArray outBuf, jlongArray outLenArr, jint pad, jint useHybrid)
{
    jbyte* in = env->GetByteArrayElements(data, nullptr);
    size_t inLen = (size_t)dataLen;
    size_t outLen = 0;
    unsigned char* out = nullptr;

    if (outBuf) {
        outLen = env->GetArrayLength(outBuf);
        out = (unsigned char*)env->GetByteArrayElements(outBuf, nullptr);
    }

    RSAStatusCode st = RSA_Encrypt((RSAPublicKeyHandle)handle,
                                   (unsigned char*)in, inLen,
                                   out, &outLen, (RSAPaddingScheme)pad, useHybrid);

    if (st == RSA_ERROR_BUFFER_TOO_SMALL || st == RSA_SUCCESS) {
        jlong len64 = (jlong)outLen;
        env->SetLongArrayRegion(outLenArr, 0, 1, &len64);
    }

    if (outBuf && out)
        env->ReleaseByteArrayElements(outBuf, (jbyte*)out, 0);
    env->ReleaseByteArrayElements(data, in, 0);
    return st;
}

// ===== 7. Decrypt =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1Decrypt
  (JNIEnv* env, jobject, jlong handle, jbyteArray inBuf, jlong inLen,
   jbyteArray outBuf, jlongArray outLenArr, jint pad, jint useHybrid)
{
    jbyte* enc = env->GetByteArrayElements(inBuf, nullptr);
    size_t encLen = (size_t)inLen;
    size_t outLen = 0;
    unsigned char* out = nullptr;

    if (outBuf) {
        outLen = env->GetArrayLength(outBuf);
        out = (unsigned char*)env->GetByteArrayElements(outBuf, nullptr);
    }

    RSAStatusCode st = RSA_Decrypt((RSAPrivateKeyHandle)handle,
                                   (unsigned char*)enc, encLen,
                                   out, &outLen, (RSAPaddingScheme)pad, useHybrid);

    if (st == RSA_ERROR_BUFFER_TOO_SMALL || st == RSA_SUCCESS) {
        jlong len64 = (jlong)outLen;
        env->SetLongArrayRegion(outLenArr, 0, 1, &len64);
    }

    if (outBuf && out)
        env->ReleaseByteArrayElements(outBuf, (jbyte*)out, 0);
    env->ReleaseByteArrayElements(inBuf, enc, 0);
    return st;
}

// ===== 8. EncryptFile =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1EncryptFile
  (JNIEnv* env, jobject, jlong pubHandle, jstring inFile, jstring outFile,
   jint pad, jint fmt, jint useHybrid)
{
    const char* in = env->GetStringUTFChars(inFile, nullptr);
    const char* out = env->GetStringUTFChars(outFile, nullptr);
    RSAStatusCode st = RSA_EncryptFile((RSAPublicKeyHandle)pubHandle, in, out,
                                       (RSAPaddingScheme)pad, (RSAOutputFormat)fmt, useHybrid);
    env->ReleaseStringUTFChars(inFile, in);
    env->ReleaseStringUTFChars(outFile, out);
    return st;
}

// ===== 9. DecryptFile =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1DecryptFile
  (JNIEnv* env, jobject, jlong privHandle, jstring inFile, jstring outFile,
   jint pad, jint fmt, jint useHybrid)
{
    const char* in = env->GetStringUTFChars(inFile, nullptr);
    const char* out = env->GetStringUTFChars(outFile, nullptr);
    RSAStatusCode st = RSA_DecryptFile((RSAPrivateKeyHandle)privHandle, in, out,
                                       (RSAPaddingScheme)pad, (RSAOutputFormat)fmt, useHybrid);
    env->ReleaseStringUTFChars(inFile, in);
    env->ReleaseStringUTFChars(outFile, out);
    return st;
}

// ===== 10. GetErrorMessage =====
JNIEXPORT jstring JNICALL Java_RSAInterop_RSA_1GetErrorMessage
  (JNIEnv* env, jobject, jint code)
{
    const char* msg = RSA_GetErrorMessage((RSAStatusCode)code);
    return env->NewStringUTF(msg);
}

// ===== 11. GetMaxPlaintextLength =====
JNIEXPORT jlong JNICALL Java_RSAInterop_RSA_1GetMaxPlaintextLength
  (JNIEnv*, jobject, jlong pubHandle, jint pad)
{
    size_t len = RSA_GetMaxPlaintextLength((RSAPublicKeyHandle)pubHandle, (RSAPaddingScheme)pad);
    return (jlong)len;
}

} // extern "C"