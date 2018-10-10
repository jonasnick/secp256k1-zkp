/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_MAIN_
#define _SECP256K1_MODULE_MUSIG_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_musig.h"
#include "hash.h"

/* Partial signature data structure:
 * 32 bytes partial s
 * 1 byte indicating whether the public nonce should be flipped
 */
int secp256k1_musig_partial_signature_serialize(const secp256k1_context* ctx, unsigned char *out33, const secp256k1_musig_partial_signature* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out33 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out33, sig->data, 33);
    return 1;
}

int secp256k1_musig_partial_signature_parse(const secp256k1_context* ctx, secp256k1_musig_partial_signature* sig, const unsigned char *in33) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in33 != NULL);
    memcpy(sig->data, in33, 33);
    return 1;
}

static void secp256k1_musig_coefficient(secp256k1_scalar *r, const unsigned char *ell, size_t idx) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, ell, 32);
    while (idx > 0) {
        unsigned char c = idx;
        secp256k1_sha256_write(&sha, &c, 1);
        idx /= 0x100;
    }
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(r, buf, NULL);
}

static int secp256k1_musig_compute_ell(const secp256k1_context *ctx, unsigned char *ell, const secp256k1_pubkey *pk, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_sha256_initialize(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t serlen = sizeof(ser);
        if (!secp256k1_ec_pubkey_serialize(ctx, ser, &serlen, &pk[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        secp256k1_sha256_write(&sha, ser, serlen);
    }
    secp256k1_sha256_finalize(&sha, ell);
    return 1;
}

int secp256k1_musig_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *tweaked_pk, secp256k1_pubkey *combined_pk, const secp256k1_pubkey *pk, size_t np) {
    size_t i;
    unsigned char ell[32];
    secp256k1_gej musigj;
    secp256k1_ge musigp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(pk != NULL);

    if (!secp256k1_musig_compute_ell(ctx, ell, pk, np)) {
        return 0;
    }

    secp256k1_gej_set_infinity(&musigj);
    for (i = 0; i < np; i++) {
        secp256k1_gej termj;
        secp256k1_gej pkj;
        secp256k1_ge pkp;
        secp256k1_scalar mc;

        if (!secp256k1_pubkey_load(ctx, &pkp, &pk[i])) {
            return 0;
        }
        secp256k1_gej_set_ge(&pkj, &pkp);
        secp256k1_musig_coefficient(&mc, ell, i);
        secp256k1_ecmult(&ctx->ecmult_ctx, &termj, &pkj, &mc, NULL);

        secp256k1_gej_add_var(&musigj, &musigj, &termj, NULL);

        if (tweaked_pk != NULL) {
            secp256k1_ge_set_gej(&pkp, &termj);
            secp256k1_pubkey_save(&tweaked_pk[i], &pkp);
        }
    }
    if (secp256k1_gej_is_infinity(&musigj)) {
        return 0;
    }

    secp256k1_ge_set_gej(&musigp, &musigj);
    secp256k1_pubkey_save(combined_pk, &musigp);
    return 1;
}

int secp256k1_musig_init(const secp256k1_context* ctx, secp256k1_scratch *scratch, secp256k1_musig_config *musig_config, const secp256k1_pubkey *pks, const size_t n) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(musig_config != NULL);
    ARG_CHECK(pks != NULL);

    musig_config->scratch = scratch;
    musig_config->n = n;

    if (secp256k1_scratch_allocate_frame(scratch, n * sizeof(secp256k1_pubkey), 1) == 0) {
        return 0;
    }
    musig_config->pks = (secp256k1_pubkey *)secp256k1_scratch_alloc(scratch, n * sizeof(secp256k1_pubkey));
    if (!secp256k1_musig_pubkey_combine(ctx, NULL, &musig_config->combined_pk, pks, musig_config->n)) {
        secp256k1_scratch_deallocate_frame(scratch);
        return 0;
    }
    if (!secp256k1_musig_compute_ell(ctx, musig_config->ell, pks, n)) {
        return 0;
    }
    return 1;
}

int secp256k1_musig_config_destroy(const secp256k1_context* ctx, secp256k1_musig_config *musig_config) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(musig_config != NULL);

    secp256k1_scratch_deallocate_frame(musig_config->scratch);
    return 1;
}

int secp256k1_musig_pubkey(const secp256k1_context* ctx, secp256k1_pubkey *combined_pk, const secp256k1_musig_config *musig_config) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(combined_pk != NULL);
    ARG_CHECK(musig_config != NULL);

    memcpy(combined_pk, &musig_config->combined_pk, sizeof(secp256k1_pubkey));
    return 1;
}

int secp256k1_musig_tweak_secret_key(const secp256k1_context* ctx, secp256k1_musig_secret_key *out, const unsigned char *seckey, const secp256k1_pubkey *pk, size_t np, size_t my_index) {
    int overflow;
    unsigned char ell[32];
    secp256k1_scalar x, y;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(pk != NULL);

    secp256k1_scalar_set_b32(&x, seckey, &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_musig_compute_ell(ctx, ell, pk, np)) {
        return 0;
    }
    secp256k1_musig_coefficient(&y, ell, my_index);

    secp256k1_scalar_mul(&x, &x, &y);
    secp256k1_scalar_get_b32(out->data, &x);

    return 1;
}

int secp256k1_musig_signer_data_initialize(const secp256k1_context* ctx, secp256k1_musig_signer_data *data, const secp256k1_musig_config *musig_config, size_t index, const unsigned char *noncommit) {
    (void) ctx;
    ARG_CHECK(data != NULL);
    ARG_CHECK(musig_config != NULL);
    ARG_CHECK(noncommit != NULL);
    memset(data, 0, sizeof(*data));
    data->index = index;
    memcpy(&data->pubkey, &musig_config->pks[index], sizeof(secp256k1_pubkey));
    memcpy(data->noncommit, noncommit, 32);
    return 1;
}

int secp256k1_musig_multisig_generate_nonce(const secp256k1_context* ctx, unsigned char *secnon, secp256k1_pubkey *pubnon, unsigned char *noncommit, const unsigned char *seckey, const unsigned char *msg32, const unsigned char *rngseed) {
    unsigned char commit[33];
    size_t commit_size = sizeof(commit);
    secp256k1_sha256 sha;
    secp256k1_scalar secs;
    secp256k1_gej rj;
    secp256k1_ge rp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secnon != NULL);
    ARG_CHECK(pubnon != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(rngseed != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, seckey, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_write(&sha, rngseed, 32);
    secp256k1_sha256_finalize(&sha, secnon);

    secp256k1_scalar_set_b32(&secs, secnon, NULL);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &secs);
    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(pubnon, &rp);

    if (noncommit != NULL) {
        secp256k1_sha256_initialize(&sha);
        secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, pubnon, SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_write(&sha, commit, commit_size);
        secp256k1_sha256_finalize(&sha, noncommit);
    }
    return 1;
}

/* TODO: needs scratchspace? */
/* don't know how many pubkeys?? */
typedef struct {
    unsigned char msg[32];
    secp256k1_pubkey my_pubnon;
    unsigned char my_secnon[32];
    unsigned char *noncommits;
    size_t my_index;
} secp256k1_musig_session;

int secp256k1_musig_session_start(const secp256k1_context* ctx, secp256k1_musig_session *session, secp256k1_musig_secret_key *musig_seckey, unsigned char *my_noncommit, const secp256k1_musig_config *musig_config, size_t my_index, const unsigned char *seckey, const unsigned char *msg32, const unsigned char *rngseed) {
    secp256k1_scalar sk, musig_coeff;
    int overflow;

    memcpy(session->msg, msg32, 32);
    if (!secp256k1_musig_multisig_generate_nonce(ctx, session->my_secnon, &session->my_pubnon, my_noncommit, seckey, session->msg, rngseed)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&sk, seckey, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_musig_coefficient(&musig_coeff, musig_config->ell, my_index);
    secp256k1_scalar_mul(&sk, &musig_coeff, &sk);
    secp256k1_scalar_get_b32(musig_seckey->data, &sk);

    return 1;
}

int secp256k1_musig_session_get_nonce(const secp256k1_context* ctx, secp256k1_musig_session* session, secp256k1_pubkey *my_pubnon, const secp256k1_musig_config *musig_config, const unsigned char **noncommits) {
    (void) ctx;
    if (secp256k1_scratch_allocate_frame(musig_config->scratch, musig_config->n * 32, 1) == 0) {
        return 0;
    }

    session->noncommits = (unsigned char *)secp256k1_scratch_alloc(musig_config->scratch, musig_config->n * 32);
    memcpy(session->noncommits, noncommits, n * 32);
    memcpy(my_pubnon, &session->my_pubnon, 33);
    return 1;
}


/* TODO */
/*
int secp256k1_musig_set_nonces(const secp256k1_context* ctx, const secp256k1_musig_config *musig_config, secp256k1_musig_session* session, const secp256k1_pubkey *pubnons) {
}
*/
/* TODO: you also want to know who did it... */
/* TODO: delete nonce from session if it's wrong... */
int secp256k1_musig_set_nonce(const secp256k1_context* ctx, secp256k1_musig_signer_data *data, const secp256k1_pubkey *pubnon) {
    unsigned char commit[33];
    size_t commit_size = sizeof(commit);
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(pubnon != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_ec_pubkey_serialize(ctx, commit, &commit_size, pubnon, SECP256K1_EC_COMPRESSED);
    secp256k1_sha256_write(&sha, commit, commit_size);
    secp256k1_sha256_finalize(&sha, commit);

    if (memcmp(commit, data->noncommit, 32) != 0) {
        return 0;
    }
    memcpy(&data->pubnon, pubnon, sizeof(*pubnon));
    data->present = 1;
    return 1;
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, secp256k1_musig_partial_signature *partial_sig, secp256k1_musig_validation_aux *aux, unsigned char *secnon, const secp256k1_musig_config *musig_config, const unsigned char *seckey, const unsigned char *msg32, const secp256k1_musig_signer_data *data, size_t my_index, const unsigned char *sec_adaptor) {
    unsigned char buf[33];
    size_t bufsize = 33;
    secp256k1_gej total_rj;
    secp256k1_ge total_r;
    secp256k1_sha256 sha;
    size_t i;
    int overflow;
    secp256k1_scalar sk;
    secp256k1_scalar e, k;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(scratch != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(aux != NULL);
    ARG_CHECK(musig_config != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(secnon != NULL);
    ARG_CHECK(data != NULL);

    /* Should this be an ARG_CHECK ? */
    if (!data[my_index].present) {
        return 0;
    }

    secp256k1_scalar_set_b32(&k, secnon, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&k)) {
        return 0;
    }

    /* compute aggregate R, saving partial-R in the partial_signature structure */
    secp256k1_gej_set_infinity(&total_rj);
    for (i = 0; i < musig_config->n; i++) {
        secp256k1_ge rp;
        if (data[i].present == 0) {
            return 0;
        }
        if (!secp256k1_pubkey_load(ctx, &rp, &data[i].pubnon)) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&total_rj, &total_rj, &rp, NULL);
    }
    if (secp256k1_gej_is_infinity(&total_rj)) {
        return 0;
    }
    if (!secp256k1_gej_has_quad_y_var(&total_rj)) {
        secp256k1_gej_neg(&total_rj, &total_rj);
        secp256k1_scalar_negate(&k, &k);
        partial_sig->data[32] = 1;
    } else {
        partial_sig->data[32] = 0;
    }
    secp256k1_ge_set_gej(&total_r, &total_rj);

    /* build message hash */
    secp256k1_sha256_initialize(&sha);
    secp256k1_fe_normalize(&total_r.x);
    secp256k1_fe_get_b32(buf, &total_r.x);
    secp256k1_sha256_write(&sha, buf, 32);
    memcpy(&aux->data[32], buf, 32);
    secp256k1_ec_pubkey_serialize(ctx, buf, &bufsize, &musig_config->combined_pk, SECP256K1_EC_COMPRESSED);
    VERIFY_CHECK(bufsize == 33);
    secp256k1_sha256_write(&sha, buf, bufsize);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, aux->data);

    secp256k1_scalar_set_b32(&e, aux->data, NULL);

    /* Sign */
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    if (sec_adaptor != NULL) {
        secp256k1_scalar offs;
        secp256k1_scalar_set_b32(&offs, sec_adaptor, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_negate(&offs, &offs);
        secp256k1_scalar_add(&e, &e, &offs);
    }
    secp256k1_scalar_get_b32(&partial_sig->data[0], &e);
    secp256k1_scalar_clear(&sk);
    secp256k1_scalar_clear(&k);
    /* Set secnon to zero such that consecutive partial signing attempts fail */
    secp256k1_scalar_get_b32(secnon, &k);

    return 1;
}

int secp256k1_musig_partial_sig_combine(const secp256k1_context* ctx, secp256k1_schnorrsig *sig, const secp256k1_musig_config *musig_config, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_validation_aux *aux) {
    size_t i;
    secp256k1_scalar s;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(musig_config != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(aux != NULL);

    secp256k1_scalar_clear(&s);
    for (i = 0; i < musig_config->n; i++) {
        int overflow;
        secp256k1_scalar term;

        secp256k1_scalar_set_b32(&term, partial_sig[i].data, &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_add(&s, &s, &term);
    }

    memcpy(&sig->data[0], &aux->data[32], 32);
    secp256k1_scalar_get_b32(&sig->data[32], &s);

    return 1;
}

int secp256k1_musig_adaptor_signature_extract_secret(const secp256k1_context* ctx, unsigned char *sec_adaptor, const secp256k1_musig_config *musig_config, const secp256k1_schnorrsig *full_sig, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_partial_signature *adaptor_sig) {
    secp256k1_scalar s;
    secp256k1_scalar term;
    int overflow;
    (void) ctx;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sec_adaptor != NULL);
    ARG_CHECK(musig_config != NULL);
    ARG_CHECK(full_sig != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);

    secp256k1_scalar_set_b32(&s, &full_sig->data[32], &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&term, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&term, &term);
    secp256k1_scalar_add(&s, &s, &term);
    secp256k1_scalar_set_b32(&term, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_negate(&term, &term);
    secp256k1_scalar_add(&s, &s, &term);

    secp256k1_scalar_get_b32(sec_adaptor, &s);
    return 1;
}

int secp256k1_musig_adaptor_signature_adapt(const secp256k1_context* ctx, secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_partial_signature *adaptor_sig, const unsigned char *sec_adaptor) {
    secp256k1_scalar s;
    secp256k1_scalar t;
    int overflow;

    (void) ctx;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(adaptor_sig != NULL);
    ARG_CHECK(sec_adaptor != NULL);

    secp256k1_scalar_set_b32(&s, adaptor_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&t, sec_adaptor, &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_scalar_add(&s, &s, &t);
    secp256k1_scalar_get_b32(partial_sig->data, &s);
    partial_sig->data[32] = adaptor_sig->data[32];

    return 1;
}

int secp256k1_musig_adaptor_signature_extract(const secp256k1_context* ctx, secp256k1_pubkey *pub_adaptor, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_signer_data *data, const secp256k1_musig_validation_aux *aux) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pub_adaptor != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(aux != NULL);

    if (!data->present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, aux->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_pubkey_load(ctx, &rp, &data->pubkey);

    if (!secp256k1_pubkey_load(ctx, &rp, &data->pubnon)) {
        return 0;
    }

    if (!secp256k1_schnorrsig_real_verify(ctx, &rj, &s, &e, &data->pubkey)) {
        return 0;
    }
    if (!partial_sig->data[32]) {
        secp256k1_ge_neg(&rp, &rp);
    }

    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);
    if (secp256k1_gej_is_infinity(&rj)) {
        return 0;
    }

    secp256k1_ge_set_gej(&rp, &rj);
    secp256k1_pubkey_save(pub_adaptor, &rp);
    return 1;
}

int secp256k1_musig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_partial_signature *partial_sig, const secp256k1_musig_signer_data *data, const secp256k1_musig_validation_aux *aux) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge rp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(data != NULL);
    ARG_CHECK(aux != NULL);

    if (!data->present) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, partial_sig->data, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_set_b32(&e, aux->data, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &rp, &data->pubnon)) {
        return 0;
    }

    if (!secp256k1_schnorrsig_real_verify(ctx, &rj, &s, &e, &data->pubkey)) {
        return 0;
    }
    if (!partial_sig->data[32]) {
        secp256k1_ge_neg(&rp, &rp);
    }
    secp256k1_gej_add_ge_var(&rj, &rj, &rp, NULL);

    return secp256k1_gej_is_infinity(&rj);
}

#endif
