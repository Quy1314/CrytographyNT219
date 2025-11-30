#include <jni.h>
#include "AESLibraryJNI.h"
#include <windows.h>

typedef void (__cdecl *FUNC_GENKEY)(unsigned char*, unsigned char*);
typedef int  (__cdecl *FUNC_SAVE)(const char*, const unsigned char*, const unsigned char*);
typedef int  (__cdecl *FUNC_LOAD)(const char*, unsigned char*, unsigned char*);
typedef int  (__cdecl *FUNC_ENC)(const unsigned char*, const unsigned char*, const char*, const char*);
typedef int  (__cdecl *FUNC_DEC)(const unsigned char*, const unsigned char*, const char*, const char*);

static HMODULE hLib = nullptr;
static FUNC_GENKEY GenKey;
static FUNC_SAVE SaveKey;
static FUNC_LOAD LoadKey;
static FUNC_ENC AESEncryptFile;
static FUNC_DEC AESDecryptFile;

jboolean LoadAESLibrary() {
    if (hLib) return JNI_TRUE;
    hLib = LoadLibraryA("AESLibrary.dll");
    if (!hLib) return JNI_FALSE;

    GenKey = (FUNC_GENKEY)GetProcAddress(hLib, "GenerateAESKey");
    SaveKey = (FUNC_SAVE)GetProcAddress(hLib, "SaveKeyToFile");
    LoadKey = (FUNC_LOAD)GetProcAddress(hLib, "LoadKeyFromFile");
    AESEncryptFile = (FUNC_ENC)GetProcAddress(hLib, "AESEncryptFile");
    AESDecryptFile = (FUNC_DEC)GetProcAddress(hLib, "AESDecryptFile");
    return (GenKey && SaveKey && LoadKey && AESEncryptFile && AESDecryptFile);
}

extern "C" {

JNIEXPORT void JNICALL Java_AESLibraryJNI_GenerateAESKey(JNIEnv* env, jobject obj, jbyteArray jkey, jbyteArray jiv) {
    if (!LoadAESLibrary()) return;
    unsigned char key[16], iv[16];
    GenKey(key, iv);
    env->SetByteArrayRegion(jkey, 0, 16, (jbyte*)key);
    env->SetByteArrayRegion(jiv, 0, 16, (jbyte*)iv);
}

JNIEXPORT jint JNICALL Java_AESLibraryJNI_SaveKeyToFile(JNIEnv* env, jobject obj, jstring jfname, jbyteArray jkey, jbyteArray jiv) {
    if (!LoadAESLibrary()) return -1;
    const char* fname = env->GetStringUTFChars(jfname, NULL);
    unsigned char key[16], iv[16];
    env->GetByteArrayRegion(jkey, 0, 16, (jbyte*)key);
    env->GetByteArrayRegion(jiv, 0, 16, (jbyte*)iv);
    int ret = SaveKey(fname, key, iv);
    env->ReleaseStringUTFChars(jfname, fname);
    return ret;
}

JNIEXPORT jint JNICALL Java_AESLibraryJNI_LoadKeyFromFile(JNIEnv* env, jobject obj, jstring jfname, jbyteArray jkey, jbyteArray jiv) {
    if (!LoadAESLibrary()) return -1;
    const char* fname = env->GetStringUTFChars(jfname, NULL);
    unsigned char key[16], iv[16];
    int ret = LoadKey(fname, key, iv);
    env->ReleaseStringUTFChars(jfname, fname);
    if (ret == 0) {
        env->SetByteArrayRegion(jkey, 0, 16, (jbyte*)key);
        env->SetByteArrayRegion(jiv, 0, 16, (jbyte*)iv);
    }
    return ret;
}

JNIEXPORT jint JNICALL Java_AESLibraryJNI_AESEncryptFile(JNIEnv* env, jobject obj, jbyteArray jkey, jbyteArray jiv, jstring jin, jstring jout) {
    if (!LoadAESLibrary()) return -1;
    const char* inFile = env->GetStringUTFChars(jin, NULL);
    const char* outFile = env->GetStringUTFChars(jout, NULL);
    unsigned char key[16], iv[16];
    env->GetByteArrayRegion(jkey, 0, 16, (jbyte*)key);
    env->GetByteArrayRegion(jiv, 0, 16, (jbyte*)iv);
    int ret = AESEncryptFile(key, iv, inFile, outFile);
    env->ReleaseStringUTFChars(jin, inFile);
    env->ReleaseStringUTFChars(jout, outFile);
    return ret;
}

JNIEXPORT jint JNICALL Java_AESLibraryJNI_AESDecryptFile(JNIEnv* env, jobject obj, jbyteArray jkey, jbyteArray jiv, jstring jin, jstring jout) {
    if (!LoadAESLibrary()) return -1;
    const char* inFile = env->GetStringUTFChars(jin, NULL);
    const char* outFile = env->GetStringUTFChars(jout, NULL);
    unsigned char key[16], iv[16];
    env->GetByteArrayRegion(jkey, 0, 16, (jbyte*)key);
    env->GetByteArrayRegion(jiv, 0, 16, (jbyte*)iv);
    int ret = AESDecryptFile(key, iv, inFile, outFile);
    env->ReleaseStringUTFChars(jin, inFile);
    env->ReleaseStringUTFChars(jout, outFile);
    return ret;
}

} // extern "C"
