#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm9.h>

static void throwIllegalState(JNIEnv *env, const char *msg) {
    jclass ex = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (ex != NULL) {
        (*env)->ThrowNew(env, ex, msg);
    }
}

static void throwIllegalArg(JNIEnv *env, const char *msg) {
    jclass ex = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (ex != NULL) {
        (*env)->ThrowNew(env, ex, msg);
    }
}

static jbyteArray toJBytes(JNIEnv *env, const uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return (*env)->NewByteArray(env, 0);
    }
    jbyteArray arr = (*env)->NewByteArray(env, (jsize) len);
    if (arr == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, arr, 0, (jsize) len, (const jbyte *) buf);
    return arr;
}

static int copyJBytes(JNIEnv *env, jbyteArray src, uint8_t **out, size_t *outlen) {
    if (src == NULL) return 0;
    jsize len = (*env)->GetArrayLength(env, src);
    if (len < 0) return 0;
    uint8_t *buf = (uint8_t *) malloc((size_t) len);
    if (!buf) return 0;
    (*env)->GetByteArrayRegion(env, src, 0, len, (jbyte *) buf);
    *out = buf;
    *outlen = (size_t) len;
    return 1;
}

JNIEXPORT jobjectArray JNICALL Java_alg_bc_nation_sm9_Sm9Native_kgcGenerateMasterKeyPair
        (JNIEnv *env, jclass clazz, jint purpose) {
    (void) clazz;

    uint8_t msk_der_buf[1024];
    size_t msk_der_len = 0;
    uint8_t mpk_der_buf[1024];
    size_t mpk_der_len = 0;

    if (purpose == 1) { // ENC
        SM9_ENC_MASTER_KEY msk;
        if (sm9_enc_master_key_generate(&msk) != 1) {
            throwIllegalState(env, "GmSSL: sm9_enc_master_key_generate failed");
            return NULL;
        }
        {
            uint8_t buf[1024];
            uint8_t *p = buf;
            size_t len = sizeof(buf);
            if (sm9_enc_master_key_to_der(&msk, &p, &len) != 1) {
                throwIllegalState(env, "GmSSL: sm9_enc_master_key_to_der failed");
                return NULL;
            }
            msk_der_len = (size_t)(p - buf);
            memcpy(msk_der_buf, buf, msk_der_len);
        }
        {
            uint8_t buf[1024];
            uint8_t *p = buf;
            size_t len = sizeof(buf);
            if (sm9_enc_master_public_key_to_der(&msk, &p, &len) != 1) {
                throwIllegalState(env, "GmSSL: sm9_enc_master_public_key_to_der failed");
                return NULL;
            }
            mpk_der_len = (size_t)(p - buf);
            memcpy(mpk_der_buf, buf, mpk_der_len);
        }
        if (msk_der_len == 0 || mpk_der_len == 0) {
            throwIllegalState(env, "GmSSL: DER output is empty (ENC master)");
            return NULL;
        }
    } else if (purpose == 2) { // SIGN
        SM9_SIGN_MASTER_KEY msk;
        if (sm9_sign_master_key_generate(&msk) != 1) {
            throwIllegalState(env, "GmSSL: sm9_sign_master_key_generate failed");
            return NULL;
        }
        {
            uint8_t buf[1024];
            uint8_t *p = buf;
            size_t len = sizeof(buf);
            if (sm9_sign_master_key_to_der(&msk, &p, &len) != 1) {
                throwIllegalState(env, "GmSSL: sm9_sign_master_key_to_der failed");
                return NULL;
            }
            msk_der_len = (size_t)(p - buf);
            memcpy(msk_der_buf, buf, msk_der_len);
        }
        {
            uint8_t buf[1024];
            uint8_t *p = buf;
            size_t len = sizeof(buf);
            if (sm9_sign_master_public_key_to_der(&msk, &p, &len) != 1) {
                throwIllegalState(env, "GmSSL: sm9_sign_master_public_key_to_der failed");
                return NULL;
            }
            mpk_der_len = (size_t)(p - buf);
            memcpy(mpk_der_buf, buf, mpk_der_len);
        }
        if (msk_der_len == 0 || mpk_der_len == 0) {
            throwIllegalState(env, "GmSSL: DER output is empty (SIGN master)");
            return NULL;
        }
    } else {
        throwIllegalArg(env, "purpose must be 1(ENC) or 2(SIGN)");
        return NULL;
    }

    jclass byteArrayClass = (*env)->FindClass(env, "[B");
    if (byteArrayClass == NULL) {
        return NULL;
    }

    jobjectArray ret = (*env)->NewObjectArray(env, 2, byteArrayClass, NULL);
    if (ret == NULL) {
        return NULL;
    }

    jbyteArray jmsk = toJBytes(env, msk_der_buf, msk_der_len);
    jbyteArray jmpk = toJBytes(env, mpk_der_buf, mpk_der_len);

    if (jmsk == NULL || jmpk == NULL) return NULL;
    (*env)->SetObjectArrayElement(env, ret, 0, jmsk);
    (*env)->SetObjectArrayElement(env, ret, 1, jmpk);
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_alg_bc_nation_sm9_Sm9Native_kgcDeriveUserPrivateKey
        (JNIEnv *env, jclass clazz, jint purpose, jbyteArray masterSecret, jbyteArray userIdBytes) {
    (void) clazz;

    uint8_t *msk_buf = NULL;
    size_t msk_len = 0;
    uint8_t *id_buf = NULL;
    size_t id_len = 0;
    if (!copyJBytes(env, masterSecret, &msk_buf, &msk_len) || !copyJBytes(env, userIdBytes, &id_buf, &id_len)) {
        free(msk_buf);
        free(id_buf);
        throwIllegalArg(env, "input must not be empty");
        return NULL;
    }

    uint8_t out_der_buf[1024];
    size_t out_der_len = 0;

    if (purpose == 1) { // ENC
        SM9_ENC_MASTER_KEY msk;
        const uint8_t *p = msk_buf;
        size_t plen = msk_len;
        if (sm9_enc_master_key_from_der(&msk, &p, &plen) != 1) {
            free(msk_buf); free(id_buf);
            throwIllegalArg(env, "mskEnc is not a valid GmSSL SM9 ENC MASTER KEY DER");
            return NULL;
        }
        SM9_ENC_KEY key;
        if (sm9_enc_master_key_extract_key(&msk, (const char *) id_buf, id_len, &key) != 1) {
            free(msk_buf); free(id_buf);
            throwIllegalState(env, "GmSSL: sm9_enc_master_key_extract_key failed");
            return NULL;
        }
        {
            uint8_t *op = out_der_buf;
            size_t olen = sizeof(out_der_buf);
            if (sm9_enc_key_to_der(&key, &op, &olen) != 1) {
                free(msk_buf); free(id_buf);
                throwIllegalState(env, "GmSSL: sm9_enc_key_to_der failed");
                return NULL;
            }
            out_der_len = (size_t)(op - out_der_buf);
        }
    } else if (purpose == 2) { // SIGN
        SM9_SIGN_MASTER_KEY msk;
        const uint8_t *p = msk_buf;
        size_t plen = msk_len;
        if (sm9_sign_master_key_from_der(&msk, &p, &plen) != 1) {
            free(msk_buf); free(id_buf);
            throwIllegalArg(env, "mskSign is not a valid GmSSL SM9 SIGN MASTER KEY DER");
            return NULL;
        }
        SM9_SIGN_KEY key;
        if (sm9_sign_master_key_extract_key(&msk, (const char *) id_buf, id_len, &key) != 1) {
            free(msk_buf); free(id_buf);
            throwIllegalState(env, "GmSSL: sm9_sign_master_key_extract_key failed");
            return NULL;
        }
        {
            uint8_t *op = out_der_buf;
            size_t olen = sizeof(out_der_buf);
            if (sm9_sign_key_to_der(&key, &op, &olen) != 1) {
                free(msk_buf); free(id_buf);
                throwIllegalState(env, "GmSSL: sm9_sign_key_to_der failed");
                return NULL;
            }
            out_der_len = (size_t)(op - out_der_buf);
        }
    } else {
        free(msk_buf); free(id_buf);
        throwIllegalArg(env, "purpose must be 1(ENC) or 2(SIGN)");
        return NULL;
    }

    free(msk_buf);
    free(id_buf);
    if (out_der_len == 0) {
        throwIllegalState(env, "GmSSL: DER output is empty (user key)");
        return NULL;
    }
    return toJBytes(env, out_der_buf, out_der_len);
}

JNIEXPORT jbyteArray JNICALL Java_alg_bc_nation_sm9_Sm9Native_encrypt
        (JNIEnv *env, jclass clazz, jbyteArray masterPublicEnc, jbyteArray userIdBytes, jbyteArray plaintext) {
    (void) clazz;

    uint8_t *mpk_buf = NULL; size_t mpk_len = 0;
    uint8_t *id_buf = NULL; size_t id_len = 0;
    uint8_t *pt_buf = NULL; size_t pt_len = 0;
    if (!copyJBytes(env, masterPublicEnc, &mpk_buf, &mpk_len) ||
        !copyJBytes(env, userIdBytes, &id_buf, &id_len) ||
        !copyJBytes(env, plaintext, &pt_buf, &pt_len)) {
        free(mpk_buf); free(id_buf); free(pt_buf);
        throwIllegalArg(env, "input must not be empty");
        return NULL;
    }
    if (pt_len > SM9_MAX_PLAINTEXT_SIZE) {
        free(mpk_buf); free(id_buf); free(pt_buf);
        throwIllegalArg(env, "plaintext too long (> SM9_MAX_PLAINTEXT_SIZE=255)");
        return NULL;
    }

    SM9_ENC_MASTER_KEY mpk;
    const uint8_t *p = mpk_buf;
    size_t plen = mpk_len;
    if (sm9_enc_master_public_key_from_der(&mpk, &p, &plen) != 1) {
        free(mpk_buf); free(id_buf); free(pt_buf);
        throwIllegalArg(env, "mpkEnc is not a valid GmSSL SM9 ENC MASTER PUBLIC KEY DER");
        return NULL;
    }

    uint8_t out_buf[SM9_MAX_CIPHERTEXT_SIZE];
    size_t out_len = sizeof(out_buf);
    if (sm9_encrypt(&mpk, (const char *) id_buf, id_len, pt_buf, pt_len, out_buf, &out_len) != 1) {
        free(mpk_buf); free(id_buf); free(pt_buf);
        throwIllegalState(env, "GmSSL: sm9_encrypt failed");
        return NULL;
    }

    free(mpk_buf); free(id_buf); free(pt_buf);
    return toJBytes(env, out_buf, out_len);
}

JNIEXPORT jbyteArray JNICALL Java_alg_bc_nation_sm9_Sm9Native_decrypt
        (JNIEnv *env, jclass clazz, jbyteArray userPrivateEnc, jbyteArray userIdBytes, jbyteArray ciphertext) {
    (void) clazz;

    uint8_t *sk_buf = NULL; size_t sk_len = 0;
    uint8_t *id_buf = NULL; size_t id_len = 0;
    uint8_t *ct_buf = NULL; size_t ct_len = 0;
    if (!copyJBytes(env, userPrivateEnc, &sk_buf, &sk_len) ||
        !copyJBytes(env, userIdBytes, &id_buf, &id_len) ||
        !copyJBytes(env, ciphertext, &ct_buf, &ct_len)) {
        free(sk_buf); free(id_buf); free(ct_buf);
        throwIllegalArg(env, "input must not be empty");
        return NULL;
    }

    SM9_ENC_KEY sk;
    const uint8_t *p = sk_buf;
    size_t plen = sk_len;
    if (sm9_enc_key_from_der(&sk, &p, &plen) != 1) {
        free(sk_buf); free(id_buf); free(ct_buf);
        throwIllegalArg(env, "skEnc is not a valid GmSSL SM9 ENC PRIVATE KEY DER");
        return NULL;
    }

    uint8_t out_buf[SM9_MAX_PLAINTEXT_SIZE];
    size_t out_len = sizeof(out_buf);
    if (sm9_decrypt(&sk, (const char *) id_buf, id_len, ct_buf, ct_len, out_buf, &out_len) != 1) {
        free(sk_buf); free(id_buf); free(ct_buf);
        throwIllegalState(env, "GmSSL: sm9_decrypt failed");
        return NULL;
    }

    free(sk_buf); free(id_buf); free(ct_buf);
    return toJBytes(env, out_buf, out_len);
}

JNIEXPORT jbyteArray JNICALL Java_alg_bc_nation_sm9_Sm9Native_sign
        (JNIEnv *env, jclass clazz, jbyteArray userPrivateSign, jbyteArray userIdBytes, jbyteArray message) {
    (void) clazz;

    uint8_t *sk_buf = NULL; size_t sk_len = 0;
    uint8_t *id_buf = NULL; size_t id_len = 0;
    uint8_t *msg_buf = NULL; size_t msg_len = 0;
    if (!copyJBytes(env, userPrivateSign, &sk_buf, &sk_len) ||
        !copyJBytes(env, userIdBytes, &id_buf, &id_len) ||
        !copyJBytes(env, message, &msg_buf, &msg_len)) {
        free(sk_buf); free(id_buf); free(msg_buf);
        throwIllegalArg(env, "input must not be empty");
        return NULL;
    }

    SM9_SIGN_KEY sk;
    const uint8_t *p = sk_buf;
    size_t plen = sk_len;
    if (sm9_sign_key_from_der(&sk, &p, &plen) != 1) {
        free(sk_buf); free(id_buf); free(msg_buf);
        throwIllegalArg(env, "skSign is not a valid GmSSL SM9 SIGN PRIVATE KEY DER");
        return NULL;
    }

    (void) id_buf; (void) id_len; // GmSSL 的 sign_finish 不需要 ID（verify 需要）
    SM9_SIGN_CTX ctx;
    if (sm9_sign_init(&ctx) != 1 ||
        sm9_sign_update(&ctx, msg_buf, msg_len) != 1) {
        free(sk_buf); free(id_buf); free(msg_buf);
        throwIllegalState(env, "GmSSL: sm9_sign_init/update failed");
        return NULL;
    }

    uint8_t sig[SM9_SIGNATURE_SIZE];
    size_t siglen = sizeof(sig);
    if (sm9_sign_finish(&ctx, &sk, sig, &siglen) != 1) {
        free(sk_buf); free(id_buf); free(msg_buf);
        throwIllegalState(env, "GmSSL: sm9_sign_finish failed");
        return NULL;
    }

    free(sk_buf); free(id_buf); free(msg_buf);
    return toJBytes(env, sig, siglen);
}

JNIEXPORT jboolean JNICALL Java_alg_bc_nation_sm9_Sm9Native_verify
        (JNIEnv *env, jclass clazz, jbyteArray masterPublicSign, jbyteArray userIdBytes, jbyteArray message, jbyteArray signature) {
    (void) clazz;

    uint8_t *mpk_buf = NULL; size_t mpk_len = 0;
    uint8_t *id_buf = NULL; size_t id_len = 0;
    uint8_t *msg_buf = NULL; size_t msg_len = 0;
    uint8_t *sig_buf = NULL; size_t sig_len = 0;
    if (!copyJBytes(env, masterPublicSign, &mpk_buf, &mpk_len) ||
        !copyJBytes(env, userIdBytes, &id_buf, &id_len) ||
        !copyJBytes(env, message, &msg_buf, &msg_len) ||
        !copyJBytes(env, signature, &sig_buf, &sig_len)) {
        free(mpk_buf); free(id_buf); free(msg_buf); free(sig_buf);
        throwIllegalArg(env, "input must not be empty");
        return JNI_FALSE;
    }

    SM9_SIGN_MASTER_KEY mpk;
    const uint8_t *p = mpk_buf;
    size_t plen = mpk_len;
    if (sm9_sign_master_public_key_from_der(&mpk, &p, &plen) != 1) {
        free(mpk_buf); free(id_buf); free(msg_buf); free(sig_buf);
        throwIllegalArg(env, "mpkSign is not a valid GmSSL SM9 SIGN MASTER PUBLIC KEY DER");
        return JNI_FALSE;
    }

    SM9_SIGN_CTX ctx;
    if (sm9_verify_init(&ctx) != 1 ||
        sm9_verify_update(&ctx, msg_buf, msg_len) != 1) {
        free(mpk_buf); free(id_buf); free(msg_buf); free(sig_buf);
        throwIllegalState(env, "GmSSL: sm9_verify_init/update failed");
        return JNI_FALSE;
    }

    int ok = sm9_verify_finish(&ctx, sig_buf, sig_len, &mpk, (const char *) id_buf, id_len);
    free(mpk_buf); free(id_buf); free(msg_buf); free(sig_buf);
    return ok == 1 ? JNI_TRUE : JNI_FALSE;
}


