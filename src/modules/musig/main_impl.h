/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra, Jonas Nick                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_MAIN_
#define _SECP256K1_MODULE_MUSIG_MAIN_

#include <stdint.h>
#include "include/secp256k1.h"
#include "include/secp256k1_musig.h"
#include "hash.h"

/* Computes ell = SHA256(pk[0], ..., pk[np-1]) */
static int secp256k1_musig_compute_ell(const secp256k1_context *ctx, unsigned char *ell, const secp256k1_xonly_pubkey * const* pk, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[32];
        if (!secp256k1_xonly_pubkey_serialize(ctx, ser, pk[i])) {
            return 0;
        }
        secp256k1_sha256_write(&sha, ser, 32);
    }
    secp256k1_sha256_finalize(&sha, ell);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg coefficient")||SHA256("KeyAgg coefficient"). */
static void secp256k1_musig_sha256_init_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);

    sha->s[0] = 0x6ef02c5aul;
    sha->s[1] = 0x06a480deul;
    sha->s[2] = 0x1f298665ul;
    sha->s[3] = 0x1d1134f2ul;
    sha->s[4] = 0x56a0b063ul;
    sha->s[5] = 0x52da4147ul;
    sha->s[6] = 0xf280d9d4ul;
    sha->s[7] = 0x4484be15ul;
    sha->bytes = 64;
}

/* Compute KeyAgg coefficient which is constant 1 for the second pubkey and
 * SHA256(ell, x) where ell is the hash of public keys otherwise. second_pk_x
 * can be 0 in case there is no second_pk. Assumes both field elements x and
 * second_pk_x are normalized. */
static void secp256k1_musig_keyaggcoef_internal(secp256k1_scalar *r, const unsigned char *ell, const secp256k1_fe *x, const secp256k1_fe *second_pk_x) {
    secp256k1_sha256 sha;
    unsigned char buf[32];

    if (secp256k1_fe_cmp_var(x, second_pk_x) == 0) {
        secp256k1_scalar_set_int(r, 1);
    } else {
        secp256k1_musig_sha256_init_tagged(&sha);
        secp256k1_sha256_write(&sha, ell, 32);
        secp256k1_fe_get_b32(buf, x);
        secp256k1_sha256_write(&sha, buf, 32);
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(r, buf, NULL);
    }
}

static void secp256k1_musig_keyaggcoef(secp256k1_scalar *r, const secp256k1_musig_pre_session *pre_session, secp256k1_fe *x) {
    secp256k1_fe second_pk_x;
    int ret;
    ret = secp256k1_fe_set_b32(&second_pk_x, pre_session->second_pk);
    VERIFY_CHECK(ret);
    secp256k1_musig_keyaggcoef_internal(r, pre_session->pk_hash, x, &second_pk_x);
}

typedef struct {
    const secp256k1_context *ctx;
    /* ell is the hash of the public keys */
    unsigned char ell[32];
    const secp256k1_xonly_pubkey * const* pks;
    secp256k1_fe second_pk_x;
} secp256k1_musig_pubkey_combine_ecmult_data;

/* Callback for batch EC multiplication to compute ell_0*P0 + ell_1*P1 + ...  */
static int secp256k1_musig_pubkey_combine_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_musig_pubkey_combine_ecmult_data *ctx = (secp256k1_musig_pubkey_combine_ecmult_data *) data;
    int ret;
    ret = secp256k1_xonly_pubkey_load(ctx->ctx, pt, ctx->pks[idx]);
    /* pubkey_load can't fail because the same pks have already been loaded (and
     * we test this) */
    VERIFY_CHECK(ret);
    secp256k1_musig_keyaggcoef_internal(sc, ctx->ell, &pt->x, &ctx->second_pk_x);
    return 1;
}

static const uint64_t pre_session_magic = 0xf4adbbdf7c7dd304UL;

int secp256k1_musig_pubkey_combine(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, secp256k1_xonly_pubkey *combined_pk, secp256k1_musig_pre_session *pre_session, const secp256k1_xonly_pubkey * const* pubkeys, size_t n_pubkeys) {
    secp256k1_musig_pubkey_combine_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    int pk_parity;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;
    /* No point on the curve has an X coordinate equal to 0 */
    secp256k1_fe_set_int(&ecmult_data.second_pk_x, 0);
    for (i = 1; i < n_pubkeys; i++) {
        secp256k1_ge pt;
        if (!secp256k1_xonly_pubkey_load(ctx, &pt, pubkeys[i])) {
            return 0;
        }
        if (secp256k1_memcmp_var(pubkeys[0], pubkeys[i], sizeof(*pubkeys[0])) != 0) {
            ecmult_data.second_pk_x = pt.x;
            break;
        }
    }

    if (!secp256k1_musig_compute_ell(ctx, ecmult_data.ell, pubkeys, n_pubkeys)) {
        return 0;
    }
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, &ctx->ecmult_ctx, scratch, &pkj, NULL, secp256k1_musig_pubkey_combine_callback, (void *) &ecmult_data, n_pubkeys)) {
        /* The current implementation of ecmult_multi_var makes this code unreachable with tests. */
        return 0;
    }
    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    pk_parity = secp256k1_extrakeys_ge_even_y(&pkp);
    secp256k1_xonly_pubkey_save(combined_pk, &pkp);

    if (pre_session != NULL) {
        pre_session->magic = pre_session_magic;
        memcpy(pre_session->pk_hash, ecmult_data.ell, 32);
        pre_session->pk_parity = pk_parity;
        pre_session->is_tweaked = 0;
        secp256k1_fe_get_b32(pre_session->second_pk, &ecmult_data.second_pk_x);
    }
    return 1;
}

int secp256k1_musig_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_musig_pre_session *pre_session, secp256k1_pubkey *output_pubkey, const secp256k1_xonly_pubkey *internal_pubkey, const unsigned char *tweak32) {
    secp256k1_ge pk;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);
    /* This function can only be called once because otherwise signing would not
     * succeed */
    ARG_CHECK(pre_session->is_tweaked == 0);

    if(!secp256k1_xonly_pubkey_tweak_add(ctx, output_pubkey, internal_pubkey, tweak32)) {
        return 0;
    }
    pre_session->internal_key_parity = pre_session->pk_parity;

    memcpy(pre_session->tweak, tweak32, 32);
    pre_session->is_tweaked = 1;

    ret = secp256k1_pubkey_load(ctx, &pk, output_pubkey);
    /* Successful xonly_pubkey_tweak_add always returns valid output_pubkey */
    VERIFY_CHECK(ret);

    pre_session->pk_parity = secp256k1_fe_is_odd(&pk.y);
    return 1;
}

static const uint64_t session_magic = 0xd92e6fc1ee41b4cbUL;

static void secp256k1_nonce_function_musig(secp256k1_scalar *k, const unsigned char *session_id, const unsigned char *key32, const unsigned char *msg32, const unsigned char *combined_pk, const unsigned char *extra_input32) {
    secp256k1_sha256 sha;
    unsigned char seed[32];
    unsigned char i;
    enum { n_extra_in = 4 };
    const unsigned char *extra_in[n_extra_in];

    /* TODO: this doesn't have the same sidechannel resistance as the BIP340
     * nonce function because the seckey feeds directly into SHA. */
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"MuSig/nonce", 11);
    secp256k1_sha256_write(&sha, session_id, 32);
    extra_in[0] = key32;
    extra_in[1] = combined_pk;
    extra_in[2] = msg32;
    extra_in[3] = extra_input32;
    for (i = 0; i < n_extra_in; i++) {
        unsigned char marker;
        if (extra_in[i] != NULL) {
            marker = 1;
            secp256k1_sha256_write(&sha, &marker, 1);
            secp256k1_sha256_write(&sha, extra_in[i], 32);
        } else {
            marker = 0;
            secp256k1_sha256_write(&sha, &marker, 1);
        }
    }
    secp256k1_sha256_finalize(&sha, seed);

    for (i = 0; i < 2; i++) {
        unsigned char buf[32];
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, seed, 32);
        secp256k1_sha256_write(&sha, &i, 1);
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(&k[i], buf, NULL);
    }
}


static void secp256k1_musig_secnonce_save(secp256k1_musig_secnonce *secnonce, secp256k1_scalar *k) {
    secp256k1_scalar_get_b32(&secnonce->data[0], &k[0]);
    secp256k1_scalar_get_b32(&secnonce->data[32], &k[1]);
}

static void secp256k1_musig_secnonce_load(secp256k1_scalar *k, secp256k1_musig_secnonce *secnonce) {
    secp256k1_scalar_set_b32(&k[0], &secnonce->data[0], NULL);
    secp256k1_scalar_set_b32(&k[1], &secnonce->data[32], NULL);
}

int secp256k1_musig_session_init(const secp256k1_context* ctx, secp256k1_musig_secnonce *secnonce, unsigned char *pubnonce66, const unsigned char *session_id32, const unsigned char *seckey, const unsigned char *msg32, const secp256k1_xonly_pubkey *combined_pk, const unsigned char *extra_input32) {
    secp256k1_scalar k[2];
    int i;
    unsigned char pk_ser[32];
    unsigned char *pk_ser_ptr = pk_ser;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    ARG_CHECK(session_id32 != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    /* Check that the seckey is valid to be able to sign for it later. */
    if (seckey != NULL) {
        secp256k1_scalar sk;
        int ret;
        ret = secp256k1_scalar_set_b32_seckey(&sk, seckey);
        /* The declassified return value indicates the validity of the seckey.
         * If this function is called correctly it is always 1. (Note:
         * declassify was only required for valgrind_ctime_test build with
         * USE_ASM_X86_64=no. */
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        ARG_CHECK(ret);
        secp256k1_scalar_clear(&sk);
    }

    if (combined_pk != NULL) {
        if (!secp256k1_xonly_pubkey_serialize(ctx, pk_ser, combined_pk)) {
            return 0;
        }
    } else {
        pk_ser_ptr = NULL;
    }
    secp256k1_nonce_function_musig(k, session_id32, seckey, msg32, pk_ser_ptr, extra_input32);
    secp256k1_musig_secnonce_save(secnonce, k);

    if (pubnonce66 != NULL) {
        for (i = 0; i < 2; i++) {
            secp256k1_ge nonce;
            secp256k1_gej noncej;
            size_t len = 33;
            int ret;
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &noncej, &k[i]);
            secp256k1_ge_set_gej(&nonce, &noncej);
            secp256k1_declassify(ctx, &nonce, sizeof(nonce));
            ret = secp256k1_eckey_pubkey_serialize(&nonce, &pubnonce66[i*33], &len, 1);
            VERIFY_CHECK(ret);
            secp256k1_scalar_clear(&k[i]);
        }
    }
    return 1;
}

static void secp256k1_musig_sum_nonces(const secp256k1_context* ctx, secp256k1_gej *summed_nonces, const unsigned char * const* pubnonces, size_t n_pubnonces) {
    size_t i;
    int j;

    secp256k1_gej_set_infinity(&summed_nonces[0]);
    secp256k1_gej_set_infinity(&summed_nonces[1]);

    for (i = 0; i < n_pubnonces; i++) {
        for (j = 0; j < 2; j++) {
            secp256k1_pubkey nonce;
            secp256k1_ge noncep;
            int ret;
            if (!secp256k1_ec_pubkey_parse(ctx, &nonce, &pubnonces[i][j*33], 33)) {
                /* Ignore if a nonce is invalid. partial_sig_verify will return
                 * 0 in that case. */
                continue;
            }
            ret = secp256k1_pubkey_load(ctx, &noncep, &nonce);
            /* Successfully parsed pubkey is always valid */
            VERIFY_CHECK(ret);
            secp256k1_gej_add_ge_var(&summed_nonces[j], &summed_nonces[j], &noncep, NULL);
        }
    }
}

static void secp256k1_musig_session_cache_load(secp256k1_scalar *b, secp256k1_scalar *e, int *combined_nonce_parity, const secp256k1_musig_session_cache *cache) {
    secp256k1_scalar_set_b32(b, &cache->data[0], NULL);
    secp256k1_scalar_set_b32(e, &cache->data[32], NULL);
    *combined_nonce_parity = cache->data[64];
}

static void secp256k1_musig_template_load(unsigned char *r32, secp256k1_scalar *s, const secp256k1_musig_template *template) {
    memcpy(r32, &template->data[0], 32);
    secp256k1_scalar_set_b32(s, &template->data[32], NULL);
}

/* Normalizes the x-coordinate of the given group element. */
static int secp256k1_xonly_ge_serialize(unsigned char *output32, secp256k1_ge *ge) {
    if (secp256k1_ge_is_infinity(ge)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_get_b32(output32, &ge->x);
    return 1;
}

/* Compute msghash = SHA256(combined_nonce, combined_pk, msg) */
static int secp256k1_musig_compute_messagehash(unsigned char *msghash, const unsigned char *combined_nonce32, const unsigned char *combined_pk32, const unsigned char *msg) {
    secp256k1_sha256 sha;

    secp256k1_schnorrsig_sha256_tagged(&sha);
    secp256k1_sha256_write(&sha, combined_nonce32, 32);
    secp256k1_sha256_write(&sha, combined_pk32, 32);
    secp256k1_sha256_write(&sha, msg, 32);
    secp256k1_sha256_finalize(&sha, msghash);
    return 1;
}

/* hash(summed_nonces[0], summed_nonces[1], combined_pk, msg) */
static int secp256k1_musig_compute_noncehash(unsigned char *noncehash, secp256k1_ge *summed_nonces, const unsigned char *combined_pk32, const unsigned char *msg) {
    unsigned char buf[32];
    secp256k1_sha256 sha;
    int i;

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < 2; i++) {
        if (!secp256k1_xonly_ge_serialize(buf, &summed_nonces[i])) {
            return 0;
        }
        secp256k1_sha256_write(&sha, buf, 32);
    }
    secp256k1_sha256_write(&sha, combined_pk32, 32);
    secp256k1_sha256_write(&sha, msg, 32);
    secp256k1_sha256_finalize(&sha, noncehash);
    return 1;
}

static int secp256k1_musig_process_nonces_internal(const secp256k1_ecmult_context* ecmult_ctx, secp256k1_ge *combined_nonce, unsigned char *noncehash, secp256k1_gej *summed_noncesj, const unsigned char *combined_pk32, const unsigned char *msg) {
    secp256k1_scalar b;
    secp256k1_gej combined_noncej;
    secp256k1_ge summed_nonces[2];

    secp256k1_ge_set_gej(&summed_nonces[0], &summed_noncesj[0]);
    secp256k1_ge_set_gej(&summed_nonces[1], &summed_noncesj[1]);
    if (!secp256k1_musig_compute_noncehash(noncehash, summed_nonces, combined_pk32, msg)) {
        return 0;
    }
    /* combined_nonce = summed_nonces[0] + b*summed_nonces[1] */
    secp256k1_scalar_set_b32(&b, noncehash, NULL);
    secp256k1_ecmult(ecmult_ctx, &combined_noncej, &summed_noncesj[1], &b, NULL);
    secp256k1_gej_add_ge(&combined_noncej, &combined_noncej, &summed_nonces[0]);
    secp256k1_ge_set_gej(combined_nonce, &combined_noncej);
    return 1;
}

int secp256k1_musig_process_nonces(const secp256k1_context* ctx, secp256k1_musig_session_cache *session_cache, secp256k1_musig_template *sig_template, int *nonce_parity, const unsigned char * const* pubnonces, size_t n_pubnonces, const unsigned char *msg32, const secp256k1_xonly_pubkey *combined_pk, const secp256k1_musig_pre_session *pre_session, const secp256k1_pubkey *adaptor) {
    secp256k1_gej summed_nonces[2];
    secp256k1_ge combined_nonce;
    unsigned char combined_pk32[32];
    secp256k1_scalar s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(session_cache != NULL);
    ARG_CHECK(sig_template != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(n_pubnonces > 0);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);

    if (!secp256k1_xonly_pubkey_serialize(ctx, combined_pk32, combined_pk)) {
        return 0;
    }

    /* Compute combined nonce and store in sig template */
    secp256k1_musig_sum_nonces(ctx, summed_nonces, pubnonces, n_pubnonces);
    /* Add public adaptor to nonce */
    if (adaptor != NULL) {
        secp256k1_ge adaptorp;
        if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&summed_nonces[0], &summed_nonces[0], &adaptorp, NULL);
    }
    if (!secp256k1_musig_process_nonces_internal(&ctx->ecmult_ctx, &combined_nonce, &session_cache->data[0], summed_nonces, combined_pk32, msg32)) {
        return 0;
    }
    if (!secp256k1_xonly_ge_serialize(&sig_template->data[0], &combined_nonce)) {
        /* unreachable with overwhelming probability */
        return 0;
    }
    /* Negate nonce if Y coordinate is not square */
    secp256k1_fe_normalize_var(&combined_nonce.y);
    /* Store nonce parity in session cache */
    session_cache->data[64] = secp256k1_fe_is_odd(&combined_nonce.y);
    if (nonce_parity != NULL) {
        *nonce_parity = session_cache->data[64];
    }

    /* Compute messagehash and store in session cache */
    secp256k1_musig_compute_messagehash(&session_cache->data[32], &sig_template->data[0], combined_pk32, msg32);

    /* If there is a tweak then set `msghash` times `tweak` to the `s`-part of the sig template.*/
    secp256k1_scalar_clear(&s);
    if (pre_session->is_tweaked) {
        secp256k1_scalar e, scalar_tweak;
        int overflow = 0;

        secp256k1_scalar_set_b32(&e, &session_cache->data[32], NULL);
        secp256k1_scalar_set_b32(&scalar_tweak, pre_session->tweak, &overflow);
        if (overflow || !secp256k1_eckey_privkey_tweak_mul(&e, &scalar_tweak)) {
            /* This mimics the behavior of secp256k1_ec_seckey_tweak_mul regarding
             * overflow and tweak being 0. */
            return 0;
        }
        if (pre_session->pk_parity) {
            secp256k1_scalar_negate(&e, &e);
        }
        secp256k1_scalar_add(&s, &s, &e);
    }
    secp256k1_scalar_get_b32(&sig_template->data[32], &s);
    return 1;
}

int secp256k1_musig_partial_signature_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_musig_partial_signature* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out32, sig->data, 32);
    return 1;
}

int secp256k1_musig_partial_signature_parse(const secp256k1_context* ctx, secp256k1_musig_partial_signature* sig, const unsigned char *in32) {
    secp256k1_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in32 != NULL);

    secp256k1_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&tmp);
        return 0;
    }
    secp256k1_scalar_get_b32(sig->data, &tmp);
    secp256k1_scalar_clear(&tmp);
    return 1;
}

static void secp256k1_musig_partial_signature_load(secp256k1_scalar *s, const secp256k1_musig_partial_signature* sig) {
    int overflow;
    secp256k1_scalar_set_b32(s, sig->data, &overflow);
    /* Parsed signatures can not overflow */
    VERIFY_CHECK(!overflow);
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, secp256k1_musig_partial_signature *partial_sig, secp256k1_musig_secnonce *secnonce, const secp256k1_keypair *keypair, const secp256k1_musig_pre_session *pre_session, const secp256k1_musig_session_cache *session_cache) {
    secp256k1_scalar sk;
    secp256k1_ge pk;
    secp256k1_scalar e, b, k[2];
    secp256k1_scalar mu;
    int combined_nonce_parity;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(secnonce != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);
    ARG_CHECK(session_cache != NULL);
    {
        /* Check in constant time if secnonce has been zeroed. */
        size_t i;
        unsigned char secnonce_acc = 0;
        for (i = 0; i < sizeof(*secnonce); i++) {
            secnonce_acc |= secnonce->data[i];
        }
        secp256k1_declassify(ctx, &secnonce_acc, sizeof(secnonce_acc));
        ARG_CHECK(secnonce_acc != 0);
    }

    secp256k1_musig_secnonce_load(k, secnonce);
    memset(secnonce, 0, sizeof(*secnonce));

    /* Obtain the signer's public key point and determine if the sk is
     * negated before signing. That happens if if the signer's pubkey has an odd
     * Y coordinate XOR the MuSig-combined pubkey has an odd Y coordinate XOR
     * (if tweaked) the internal key has an odd Y coordinate.
     *
     * This can be seen by looking at the sk key belonging to `combined_pk`.
     * Let's define
     * P' := mu_0*|P_0| + ... + mu_n*|P_n| where P_i is the i-th public key
     * point x_i*G, mu_i is the i-th KeyAgg coefficient and |.| is a function
     * that normalizes a point to an even Y by negating if necessary similar to
     * secp256k1_extrakeys_ge_even_y. Then we have
     * P := |P'| + t*G where t is the tweak.
     * And the combined xonly public key is
     * |P| = x*G
     *      where x = sum_i(b_i*mu_i*x_i) + b'*t
     *            b' = -1 if P != |P|, 1 otherwise
     *            b_i = -1 if (P_i != |P_i| XOR P' != |P'| XOR P != |P|) and 1
     *                otherwise.
     */
    if (!secp256k1_keypair_load(ctx, &sk, &pk, keypair)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&pk.y);
    if((secp256k1_fe_is_odd(&pk.y)
            + pre_session->pk_parity
            + (pre_session->is_tweaked
                && pre_session->internal_key_parity))
            % 2 == 1) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    /* Multiply KeyAgg coefficient */
    secp256k1_fe_normalize_var(&pk.x);
    secp256k1_musig_keyaggcoef(&mu, pre_session, &pk.x);
    secp256k1_scalar_mul(&sk, &sk, &mu);

    secp256k1_musig_session_cache_load(&b, &e, &combined_nonce_parity, session_cache);
    if (combined_nonce_parity) {
        secp256k1_scalar_negate(&k[0], &k[0]);
        secp256k1_scalar_negate(&k[1], &k[1]);
    }

    /* Sign */
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_mul(&k[1], &b, &k[1]);
    secp256k1_scalar_add(&k[0], &k[0], &k[1]);
    secp256k1_scalar_add(&e, &e, &k[0]);
    secp256k1_scalar_get_b32(&partial_sig->data[0], &e);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&k[0]);
    secp256k1_scalar_clear(&k[1]);
    return 1;
}

int secp256k1_musig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_partial_signature *partial_sig, const unsigned char *pubnonce66, const secp256k1_xonly_pubkey *pubkey, const secp256k1_musig_pre_session *pre_session, const secp256k1_musig_session_cache *session_cache) {
    secp256k1_scalar mu, b, e, s;
    secp256k1_gej pkj;
    secp256k1_ge nonces[2];
    secp256k1_gej rj;
    secp256k1_gej tmp;
    secp256k1_ge pkp;
    int i;
    int combined_nonce_parity;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubnonce66 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(pre_session != NULL);
    ARG_CHECK(pre_session->magic == pre_session_magic);
    ARG_CHECK(session_cache != NULL);

    secp256k1_musig_session_cache_load(&b, &e, &combined_nonce_parity, session_cache);

    /* Compute "effective" nonce rj = nonces[0] + b*nonces[1] */
    /* TODO: use multiexp */
    for (i = 0; i < 2; i++) {
        secp256k1_pubkey n;
        int ret;
        if (!secp256k1_ec_pubkey_parse(ctx, &n, &pubnonce66[i*33], 33)) {
            return 0;
        }
        ret = secp256k1_pubkey_load(ctx, &nonces[i], &n);
        /* Successfully parsed pubkey is always valid */
        VERIFY_CHECK(ret);
    }
    secp256k1_gej_set_ge(&rj, &nonces[1]);
    secp256k1_ecmult(&ctx->ecmult_ctx, &rj, &rj, &b, NULL);
    secp256k1_gej_add_ge_var(&rj, &rj, &nonces[0], NULL);

    if (!secp256k1_xonly_pubkey_load(ctx, &pkp, pubkey)) {
        return 0;
    }
    /* Multiplying the messagehash by the KeyAgg coefficient is equivalent
     * to multiplying the signer's public key by the coefficient, except
     * much easier to do. */
    secp256k1_musig_keyaggcoef(&mu, pre_session, &pkp.x);
    secp256k1_scalar_mul(&e, &e, &mu);

    /* If the MuSig-combined point has an odd Y coordinate, the signers will
     * sign for the negation of their individual xonly public key such that the
     * combined signature is valid for the MuSig aggregated xonly key. If the
     * MuSig-combined point was tweaked then `e` is negated if the combined key
     * has an odd Y coordinate XOR the internal key has an odd Y coordinate.*/
    if (pre_session->pk_parity
            != (pre_session->is_tweaked
                && pre_session->internal_key_parity)) {
        secp256k1_scalar_negate(&e, &e);
    }

    secp256k1_musig_partial_signature_load(&s, partial_sig);
    /* Compute -s*G + e*pkj + rj */
    secp256k1_scalar_negate(&s, &s);
    secp256k1_gej_set_ge(&pkj, &pkp);
    secp256k1_ecmult(&ctx->ecmult_ctx, &tmp, &pkj, &e, &s);
    if (combined_nonce_parity) {
        secp256k1_gej_neg(&rj, &rj);
    }
    secp256k1_gej_add_var(&tmp, &tmp, &rj, NULL);

    return secp256k1_gej_is_infinity(&tmp);
}

int secp256k1_musig_partial_sig_combine(const secp256k1_context* ctx, unsigned char *sig64, const secp256k1_musig_template *sig_template, const secp256k1_musig_partial_signature * const* partial_sigs, size_t n_sigs) {
    size_t i;
    secp256k1_scalar s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(sig_template != NULL);
    ARG_CHECK(partial_sigs != NULL);

    secp256k1_musig_template_load(&sig64[0], &s, sig_template);
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar term;
        secp256k1_musig_partial_signature_load(&term, partial_sigs[i]);
        secp256k1_scalar_add(&s, &s, &term);
    }
    secp256k1_scalar_get_b32(&sig64[32], &s);

    return 1;
}

int secp256k1_musig_partial_sig_adapt(const secp256k1_context* ctx, secp256k1_musig_partial_signature *adaptor_sig, const secp256k1_musig_partial_signature *partial_sig, const unsigned char *sec_adaptor32, int nonce_parity) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);

    secp256k1_musig_partial_signature_load(&s, partial_sig);
    secp256k1_scalar_set_b32(&t, sec_adaptor32, &overflow);
    if (overflow) {
        secp256k1_scalar_clear(&t);
        return 0;
    }

    if (nonce_parity) {
        secp256k1_scalar_negate(&t, &t);
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(adaptor_sig->data, &s);
    secp256k1_scalar_clear(&t);
    return 1;
}

int secp256k1_musig_extract_secret_adaptor(const secp256k1_context* ctx, unsigned char *sec_adaptor32, const unsigned char *sig64, const secp256k1_musig_partial_signature *partial_sigs, size_t n_partial_sigs, int nonce_parity) {
    secp256k1_scalar t;
    secp256k1_scalar s;
    int overflow;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(partial_sigs != NULL);

    secp256k1_scalar_set_b32(&t, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&t, &t);

    for (i = 0; i < n_partial_sigs; i++) {
        secp256k1_musig_partial_signature_load(&s, &partial_sigs[i]);
        secp256k1_scalar_add(&t, &t, &s);
    }

    if (!nonce_parity) {
        secp256k1_scalar_negate(&t, &t);
    }
    secp256k1_scalar_get_b32(sec_adaptor32, &t);
    secp256k1_scalar_clear(&t);
    return 1;
}
#endif
