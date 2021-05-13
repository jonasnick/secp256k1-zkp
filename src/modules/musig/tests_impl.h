/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

static int create_keypair_and_pk(secp256k1_keypair *keypair, secp256k1_xonly_pubkey *pk, const unsigned char *sk) {
    int ret;
    secp256k1_keypair keypair_tmp;
    ret = secp256k1_keypair_create(ctx, &keypair_tmp, sk);
    ret &= secp256k1_keypair_xonly_pub(ctx, pk, NULL, &keypair_tmp);
    if (keypair != NULL) {
        *keypair = keypair_tmp;
    }
    return ret;
}

/* Just a simple (non-adaptor, non-tweaked) 2-of-2 MuSig combine, sign, verify
 * test. */
void musig_simple_test(secp256k1_scratch_space *scratch) {
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    unsigned char pubnonce[2][66];
    const unsigned char *pubnonce_ptr[2];
    unsigned char msg[32];
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_musig_pre_session pre_session;
    unsigned char session_id[2][32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    secp256k1_musig_partial_signature partial_sig[2];
    const secp256k1_musig_partial_signature *partial_sig_ptr[2];
    unsigned char final_sig[64];
    secp256k1_musig_template sig_template;
    secp256k1_musig_session_cache session_cache;
    int i;

    secp256k1_testrand256(msg);
    for (i = 0; i < 2; i++) {
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 1);

    CHECK(secp256k1_musig_session_init(ctx, &secnonce[0], pubnonce[0], session_id[0], sk[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_session_init(ctx, &secnonce[1], pubnonce[1], session_id[1], sk[1], NULL, NULL, NULL) == 1);

    CHECK(secp256k1_musig_process_nonces(ctx, &session_cache, &sig_template, NULL, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, NULL) == 1);

    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[0], &secnonce[0], &keypair[0], &pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[0], pubnonce[0], &pk[0], &pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[1], &secnonce[1], &keypair[1], &pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[1], pubnonce[1], &pk[1], &pre_session, &session_cache) == 1);

    CHECK(secp256k1_musig_partial_sig_combine(ctx, final_sig, &sig_template, partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, &combined_pk) == 1);
}

void pubnonce66_summing_to_inf(unsigned char *pubnonce66) {
    secp256k1_ge ge[2];
    size_t len = 33;
    int i;
    secp256k1_gej summed_nonces[2];
    const unsigned char *pubnonce_ptr[2];

    ge[0] = secp256k1_ge_const_g;
    secp256k1_ge_neg(&ge[1], &ge[0]);

    for (i = 0; i < 2; i++) {
        secp256k1_eckey_pubkey_serialize(&ge[i], &pubnonce66[i*66], &len, 1);
        secp256k1_eckey_pubkey_serialize(&ge[i], &pubnonce66[i*66 + 33], &len, 1);
        pubnonce_ptr[i] = &pubnonce66[i*66];
    }

    secp256k1_musig_sum_nonces(ctx, summed_nonces, pubnonce_ptr, 2);
    secp256k1_gej_is_infinity(&summed_nonces[0]);
    secp256k1_gej_is_infinity(&summed_nonces[1]);
}

void musig_api_tests(secp256k1_scratch_space *scratch) {
    secp256k1_scratch_space *scratch_small;
    secp256k1_musig_partial_signature partial_sig[2];
    secp256k1_musig_partial_signature partial_sig_adapted[2];
    const secp256k1_musig_partial_signature *partial_sig_adapted_ptr[2];
    secp256k1_musig_partial_signature partial_sig_overflow;
    unsigned char final_sig[64];
    unsigned char buf[32];
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    secp256k1_keypair invalid_keypair;
    unsigned char ones[32];
    unsigned char zeros64[64] = { 0 };
    unsigned char session_id[2][32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_musig_secnonce secnonce_tmp;
    unsigned char pubnonce[2][66];
    const unsigned char *pubnonce_ptr[2];
    unsigned char invalid_pubnonce[66];
    const unsigned char *invalid_pubnonce_ptr[1];
    unsigned char inf_pubnonce[2][66];
    const unsigned char *inf_pubnonce_ptr[2];
    unsigned char combined_pnonce[66];
    unsigned char msg[32];
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_musig_pre_session pre_session;
    secp256k1_musig_pre_session pre_session_uninit;
    secp256k1_musig_template sig_template;
    secp256k1_musig_session_cache session_cache;
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    secp256k1_xonly_pubkey invalid_pk;
    const secp256k1_xonly_pubkey *invalid_pk_ptr2[2];
    const secp256k1_xonly_pubkey *invalid_pk_ptr3[3];
    unsigned char tweak[32];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    int i;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);

    memset(ones, 0xff, sizeof(ones));
    memset(&invalid_keypair, 0, sizeof(invalid_keypair));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    pubnonce66_summing_to_inf(&inf_pubnonce[0][0]);
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&pre_session_uninit, 0, sizeof(pre_session_uninit));
    memset(&invalid_pk, 0, sizeof(invalid_pk));

    secp256k1_testrand256(sec_adaptor);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(tweak);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        invalid_pk_ptr2[i] = &invalid_pk;
        invalid_pk_ptr3[i] = &pk[i];
        pubnonce_ptr[i] = pubnonce[i];
        inf_pubnonce_ptr[i] = inf_pubnonce[i];
        partial_sig_adapted_ptr[i] = &partial_sig_adapted[i];
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    invalid_pubnonce_ptr[0] = invalid_pubnonce;
    /* invalid_pk_ptr3 has two valid, one invalid pk, which is important to test
     * musig_pubkeys_combine */
    invalid_pk_ptr3[2] = &invalid_pk;

    /** main test body **/

    /* Key combination */
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_combine(none, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey_combine(sign, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 1);
    CHECK(ecount == 2);
    /* pubkey_combine does not require a scratch space */
    CHECK(secp256k1_musig_pubkey_combine(vrfy, NULL, &combined_pk, &pre_session, pk_ptr, 2) == 1);
    CHECK(ecount == 2);
    /* A small scratch space works too, but will result in using an ineffecient algorithm */
    scratch_small = secp256k1_scratch_space_create(ctx, 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch_small, &combined_pk, &pre_session, pk_ptr, 2) == 1);
    secp256k1_scratch_space_destroy(ctx, scratch_small);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, NULL, &pre_session, pk_ptr, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, NULL, pk_ptr, 2) == 1);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, NULL, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, invalid_pk_ptr2, 2) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, invalid_pk_ptr3, 3) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, pk_ptr, 0) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, NULL, 0) == 0);
    CHECK(ecount == 8);

    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 1);

    /** Tweaking */
    ecount = 0;
    {
        secp256k1_xonly_pubkey tmp_internal_pk = combined_pk;
        secp256k1_pubkey tmp_output_pk;
        secp256k1_musig_pre_session tmp_pre_session = pre_session;
        CHECK(secp256k1_musig_pubkey_tweak_add(ctx, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, tweak) == 1);
        /* Reset pre_session */
        tmp_pre_session = pre_session;
        CHECK(secp256k1_musig_pubkey_tweak_add(none, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, tweak) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_pubkey_tweak_add(sign, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, tweak) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, tweak) == 1);
        CHECK(ecount == 2);
        tmp_pre_session = pre_session;
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, NULL, &tmp_output_pk, &tmp_internal_pk, tweak) == 0);
        CHECK(ecount == 3);
        /* Uninitialized pre_session */
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &pre_session_uninit, &tmp_output_pk, &tmp_internal_pk, tweak) == 0);
        CHECK(ecount == 4);
        /* Using the same pre_session twice does not work */
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, tweak) == 1);
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, tweak) == 0);
        CHECK(ecount == 5);
        tmp_pre_session = pre_session;
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, NULL, &tmp_internal_pk, tweak) == 0);
        CHECK(ecount == 6);
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, &tmp_output_pk, NULL, tweak) == 0);
        CHECK(ecount == 7);
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, NULL) == 0);
        CHECK(ecount == 8);
        CHECK(secp256k1_musig_pubkey_tweak_add(vrfy, &tmp_pre_session, &tmp_output_pk, &tmp_internal_pk, ones) == 0);
        CHECK(ecount == 8);
    }

    /** Session creation **/
    ecount = 0;
    CHECK(secp256k1_musig_session_init(none, &secnonce[0], pubnonce[0], session_id[0], sk[0], msg, &combined_pk, ones) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_session_init(vrfy, &secnonce[0], pubnonce[0], session_id[0], sk[0], msg, &combined_pk, ones) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], sk[0], msg, &combined_pk, ones) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_init(sign, NULL, pubnonce[0], session_id[0], sk[0], msg, &combined_pk, ones) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], NULL, session_id[0], sk[0], msg, &combined_pk, ones) == 1);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], NULL, sk[0], msg, &combined_pk, ones) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], NULL, msg, &combined_pk, ones) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], sk[0], NULL, &combined_pk, ones) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], sk[0], msg, NULL, ones) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], sk[0], msg, &invalid_pk, ones) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], sk[0], msg, &combined_pk, NULL) == 1);
    CHECK(ecount == 5);

    CHECK(secp256k1_musig_session_init(sign, &secnonce[0], pubnonce[0], session_id[0], sk[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_session_init(sign, &secnonce[1], pubnonce[1], session_id[1], sk[1], NULL, NULL, NULL) == 1);

    /** Receive nonces **/
    ecount = 0;
    CHECK(secp256k1_musig_nonces_combine(none, combined_pnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_musig_nonces_combine(none, NULL, pubnonce_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_nonces_combine(none, combined_pnonce, NULL, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_nonces_combine(none, combined_pnonce, pubnonce_ptr, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_nonces_combine(none, combined_pnonce, invalid_pubnonce_ptr, 1) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_nonces_combine(none, combined_pnonce, inf_pubnonce_ptr, 2) == 0);
    CHECK(ecount == 3);

    ecount = 0;
    CHECK(secp256k1_musig_process_nonces(none, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_process_nonces(sign, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_process_nonces(vrfy, NULL, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, NULL, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, NULL, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, NULL, 2, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, invalid_pubnonce_ptr, 1, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, inf_pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 0, msg, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, NULL, &combined_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, NULL, &pre_session, &adaptor) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &invalid_pk, &pre_session, &adaptor) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, NULL, &adaptor) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session_uninit, &adaptor) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, NULL) == 1);
    CHECK(ecount == 11);
    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, (secp256k1_pubkey *)&invalid_pk) == 0);
    CHECK(ecount == 12);

    CHECK(secp256k1_musig_process_nonces(vrfy, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, &adaptor) == 1);

    ecount = 0;
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &pre_session, &session_cache) == 1);
    /* The session_id is set to 0 and subsequent signing attempts fail */
    CHECK(memcmp(&secnonce_tmp, zeros64, sizeof(secnonce_tmp)) == 0);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 1);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, NULL, &secnonce_tmp, &keypair[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 2);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], NULL, &keypair[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 3);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, NULL, &pre_session, &session_cache) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &invalid_keypair, &pre_session, &session_cache) == 0);
    CHECK(ecount == 5);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], NULL, &session_cache) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &pre_session_uninit, &session_cache) == 0);
    CHECK(ecount == 7);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &pre_session, NULL) == 0);
    CHECK(ecount == 8);

    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce[0], &keypair[0], &pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[1], &secnonce[1], &keypair[1], &pre_session, &session_cache) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_signature_serialize(none, buf, &partial_sig[0]) == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, buf, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], buf) == 1);
    CHECK(secp256k1_musig_partial_signature_parse(none, NULL, buf) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig_overflow, ones) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 4);

    /** Partial signature verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_verify(none, &partial_sig[0], pubnonce[0], &pk[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_verify(sign, &partial_sig[0], pubnonce[0], &pk[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], &pk[0], &pre_session, &session_cache) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, NULL, pubnonce[0], &pk[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], NULL, &pk[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], invalid_pubnonce, &pk[0], &pre_session, &session_cache) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], NULL, &pre_session, &session_cache) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], &invalid_pk, &pre_session, &session_cache) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], &pk[0], NULL, &session_cache) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], &pk[0], &pre_session_uninit, &session_cache) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], &pk[0], &pre_session, NULL) == 0);
    CHECK(ecount == 9);

    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], pubnonce[0], &pk[0], &pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], pubnonce[1], &pk[1], &pre_session, &session_cache) == 1);

    /** Adaptor signature verification */
    memcpy(&partial_sig_adapted[1], &partial_sig[1], sizeof(partial_sig_adapted[1]));
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], &partial_sig[0], sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_musig_partial_sig_adapt(none, NULL, &partial_sig[0], sec_adaptor, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], NULL, sec_adaptor, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], &partial_sig[0], NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], &partial_sig[0], ones, nonce_parity) == 0);
    CHECK(ecount == 3);

    /** Signing combining and verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_combine(none, final_sig, &sig_template, partial_sig_adapted_ptr, 2) == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, NULL, &sig_template, partial_sig_adapted_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, final_sig, NULL, partial_sig_adapted_ptr, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_combine(none, final_sig, &sig_template, NULL, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_combine(none, final_sig, &sig_template, partial_sig_adapted_ptr, 0) == 1);
    CHECK(ecount == 3);

    CHECK(secp256k1_musig_partial_sig_combine(none, final_sig, &sig_template, partial_sig_adapted_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, final_sig, msg, &combined_pk) == 1);

    /** Secret adaptor can be extracted from signature */
    ecount = 0;
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, final_sig, partial_sig, 2, nonce_parity) == 1);
    CHECK(memcmp(sec_adaptor, sec_adaptor1, 32) == 0);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, NULL, final_sig, partial_sig, 2, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, NULL, partial_sig, 2, 0) == 0);
    CHECK(ecount == 2);
    {
        unsigned char final_sig_tmp[64];
        memcpy(final_sig_tmp, final_sig, sizeof(final_sig_tmp));
        memcpy(&final_sig_tmp[32], ones, 32);
        CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, final_sig_tmp, partial_sig, 2, nonce_parity) == 0);
    }
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, final_sig, NULL, 2, 0) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, final_sig, partial_sig, 0, 0) == 1);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, final_sig, partial_sig, 2, 1) == 1);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
}

void musig_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    secp256k1_scalar k1[2], k2[2];

    secp256k1_nonce_function_musig(k1, args[0], args[1], args[2], args[3], args[4]);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    secp256k1_nonce_function_musig(k2, args[0], args[1], args[2], args[3], args[4]);
    CHECK(secp256k1_scalar_eq(&k1[0], &k2[0]) == 0);
    CHECK(secp256k1_scalar_eq(&k1[1], &k2[1]) == 0);
}

void musig_nonce_null(unsigned char **args, size_t n_flip) {
    secp256k1_scalar k1[2], k2[2];
    unsigned char *args_tmp;

    secp256k1_nonce_function_musig(k1, args[0], args[1], args[2], args[3], args[4]);
    args_tmp = args[n_flip];
    args[n_flip] = NULL;
    secp256k1_nonce_function_musig(k2, args[0], args[1], args[2], args[3], args[4]);
    CHECK(secp256k1_scalar_eq(&k1[0], &k2[0]) == 0);
    CHECK(secp256k1_scalar_eq(&k1[1], &k2[1]) == 0);
    args[n_flip] = args_tmp;
}

void musig_nonce_test(void) {
    unsigned char *args[5];
    unsigned char session_id[32];
    unsigned char sk[32];
    unsigned char msg[32];
    unsigned char combined_pk[32];
    unsigned char extra_input[32];
    int i, j;
    secp256k1_scalar k[5][2];

    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, session_id, sizeof(session_id));
    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, sk, sizeof(sk));
    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, msg, sizeof(msg));
    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, combined_pk, sizeof(combined_pk));
    secp256k1_rfc6979_hmac_sha256_generate(&secp256k1_test_rng, extra_input, sizeof(extra_input));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = session_id;
    args[1] = sk;
    args[2] = msg;
    args[3] = combined_pk;
    args[4] = extra_input;
    for (i = 0; i < count; i++) {
        musig_nonce_bitflip(args, 0, sizeof(session_id));
        musig_nonce_bitflip(args, 1, sizeof(sk));
        musig_nonce_bitflip(args, 2, sizeof(msg));
        musig_nonce_bitflip(args, 3, sizeof(combined_pk));
        musig_nonce_bitflip(args, 4, sizeof(extra_input));
    }
    /* Check that if any argument is NULL, a different nonce is produced than if
     * any other argument is NULL. */
    memcpy(sk, session_id, sizeof(sk));
    memcpy(msg, session_id, sizeof(msg));
    memcpy(combined_pk, session_id, sizeof(combined_pk));
    memcpy(extra_input, session_id, sizeof(extra_input));
    secp256k1_nonce_function_musig(k[0], args[0], args[1], args[2], args[3], args[4]);
    secp256k1_nonce_function_musig(k[1], args[0], NULL, args[2], args[3], args[4]);
    secp256k1_nonce_function_musig(k[2], args[0], args[1], NULL, args[3], args[4]);
    secp256k1_nonce_function_musig(k[3], args[0], args[1], args[2], NULL, args[4]);
    secp256k1_nonce_function_musig(k[4], args[0], args[1], args[2], args[3], NULL);
    for (i = 0; i < 4; i++) {
        for (j = i+1; j < 5; j++) {
            CHECK(secp256k1_scalar_eq(&k[i][0], &k[j][0]) == 0);
            CHECK(secp256k1_scalar_eq(&k[i][1], &k[j][1]) == 0);
        }
    }
}

void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    /* Throughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    unsigned char final_sig_a[64];
    unsigned char final_sig_b[64];
    secp256k1_musig_partial_signature partial_sig_a[2];
    const secp256k1_musig_partial_signature *partial_sig_a_ptr[2];
    secp256k1_musig_partial_signature partial_sig_b_adapted[2];
    const secp256k1_musig_partial_signature *partial_sig_b_adapted_ptr[2];
    secp256k1_musig_partial_signature partial_sig_b[2];
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor;
    unsigned char sk_a[2][32];
    unsigned char sk_b[2][32];
    secp256k1_keypair keypair_a[2];
    secp256k1_keypair keypair_b[2];
    secp256k1_xonly_pubkey pk_a[2];
    const secp256k1_xonly_pubkey *pk_a_ptr[2];
    secp256k1_xonly_pubkey pk_b[2];
    const secp256k1_xonly_pubkey *pk_b_ptr[2];
    secp256k1_musig_pre_session pre_session_a;
    secp256k1_musig_pre_session pre_session_b;
    secp256k1_xonly_pubkey combined_pk_a;
    secp256k1_xonly_pubkey combined_pk_b;
    secp256k1_musig_secnonce secnonce_a[2];
    secp256k1_musig_secnonce secnonce_b[2];
    unsigned char pubnonce_a[2][66];
    unsigned char pubnonce_b[2][66];
    const unsigned char *pubnonce_ptr_a[2];
    const unsigned char *pubnonce_ptr_b[2];
    secp256k1_musig_template sig_template_a, sig_template_b;
    secp256k1_musig_session_cache session_cache_a, session_cache_b;
    int nonce_parity_a;
    int nonce_parity_b;
    unsigned char seed_a[2][32] = { "a0", "a1" };
    unsigned char seed_b[2][32] = { "b0", "b1" };
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";
    int i;

    /* Step 1: key setup */
    for (i = 0; i < 2; i++) {
        pk_a_ptr[i] = &pk_a[i];
        pk_b_ptr[i] = &pk_b[i];
        pubnonce_ptr_a[i] = pubnonce_a[i];
        pubnonce_ptr_b[i] = pubnonce_b[i];
        partial_sig_b_adapted_ptr[i] = &partial_sig_b_adapted[i];
        partial_sig_a_ptr[i] = &partial_sig_a[i];

        secp256k1_testrand256(sk_a[i]);
        secp256k1_testrand256(sk_b[i]);
        CHECK(create_keypair_and_pk(&keypair_a[i], &pk_a[i], sk_a[i]));
        CHECK(create_keypair_and_pk(&keypair_b[i], &pk_b[i], sk_b[i]));
    }
    secp256k1_testrand256(sec_adaptor);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pub_adaptor, sec_adaptor));

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk_a, &pre_session_a, pk_a_ptr, 2));
    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk_b, &pre_session_b, pk_b_ptr, 2));

    CHECK(secp256k1_musig_session_init(ctx, &secnonce_a[0], pubnonce_a[0], seed_a[0], sk_a[0], NULL, NULL, NULL));
    CHECK(secp256k1_musig_session_init(ctx, &secnonce_a[1], pubnonce_a[1], seed_a[1], sk_a[1], NULL, NULL, NULL));
    CHECK(secp256k1_musig_session_init(ctx, &secnonce_b[0], pubnonce_b[0], seed_b[0], sk_b[0], NULL, NULL, NULL));
    CHECK(secp256k1_musig_session_init(ctx, &secnonce_b[1], pubnonce_b[1], seed_b[1], sk_b[1], NULL, NULL, NULL));

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_process_nonces(ctx, &session_cache_a, &sig_template_a, &nonce_parity_a, pubnonce_ptr_a, 2, msg32_a, &combined_pk_a, &pre_session_a, &pub_adaptor));
    CHECK(secp256k1_musig_process_nonces(ctx, &session_cache_b, &sig_template_b, &nonce_parity_b, pubnonce_ptr_b, 2, msg32_b, &combined_pk_b, &pre_session_b, &pub_adaptor));

    /* Step 3: Signer 0 produces partial signatures for both chains. */
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_a[0], &secnonce_a[0], &keypair_a[0], &pre_session_a, &session_cache_a));
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_b[0], &secnonce_b[0], &keypair_b[0], &pre_session_b, &session_cache_b));

    /* Step 4: Signer 1 receives partial signatures, verifies them and creates a
     * partial signature to send B-coins to signer 0. */
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig_a[0], pubnonce_a[0], &pk_a[0], &pre_session_a, &session_cache_a) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig_b[0], pubnonce_b[0], &pk_b[0], &pre_session_b, &session_cache_b) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_b[1], &secnonce_b[1], &keypair_b[1], &pre_session_b, &session_cache_b));

    /* Step 5: Signer 0 adapts its own partial signature and combines it with the
     * partial signature from signer 1. This results in a complete signature which
     * is broadcasted by signer 0 to take B-coins. */
    CHECK(secp256k1_musig_partial_sig_adapt(ctx, &partial_sig_b_adapted[0], &partial_sig_b[0], sec_adaptor, nonce_parity_b));
    memcpy(&partial_sig_b_adapted[1], &partial_sig_b[1], sizeof(partial_sig_b_adapted[1]));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, final_sig_b, &sig_template_b, partial_sig_b_adapted_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig_b, msg32_b, &combined_pk_b) == 1);

    /* Step 6: Signer 1 extracts adaptor from the published signature, applies it to
     * other partial signature, and takes A-coins. */
    CHECK(secp256k1_musig_extract_secret_adaptor(ctx, sec_adaptor_extracted, final_sig_b, partial_sig_b, 2, nonce_parity_b) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_partial_sig_adapt(ctx, &partial_sig_a[0], &partial_sig_a[0], sec_adaptor_extracted, nonce_parity_a));
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_a[1], &secnonce_a[1], &keypair_a[1], &pre_session_a, &session_cache_a));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, final_sig_a, &sig_template_a, partial_sig_a_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig_a, msg32_a, &combined_pk_a) == 1);
}

void musig_combiner_test(secp256k1_scratch_space *scratch) {
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    unsigned char pubnonce[2][66];
    const unsigned char *pubnonce_ptr[2];
    unsigned char combined_pnonce[66];
    const unsigned char *combined_pnonce_ptr[1];
    unsigned char msg[32];
    secp256k1_xonly_pubkey combined_pk;
    secp256k1_musig_pre_session pre_session;
    unsigned char session_id[2][32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    int nonce_parity, nonce_parity2;
    secp256k1_musig_template sig_template, sig_template2;
    secp256k1_musig_session_cache session_cache, session_cache2;
    int i;

    secp256k1_testrand256(msg);
    for (i = 0; i < 2; i++) {
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = pubnonce[i];
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    combined_pnonce_ptr[0] = combined_pnonce;

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk, &pre_session, pk_ptr, 2) == 1);

    CHECK(secp256k1_musig_session_init(ctx, &secnonce[0], pubnonce[0], session_id[0], sk[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_session_init(ctx, &secnonce[1], pubnonce[1], session_id[1], sk[1], NULL, NULL, NULL) == 1);

    CHECK(secp256k1_musig_process_nonces(ctx, &session_cache, &sig_template, &nonce_parity, pubnonce_ptr, 2, msg, &combined_pk, &pre_session, NULL) == 1);
    /* Check that process_nonces on the result of nonces_combine gives the same result */
    CHECK(secp256k1_musig_nonces_combine(ctx, combined_pnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_musig_process_nonces(ctx, &session_cache2, &sig_template2, &nonce_parity2, combined_pnonce_ptr, 1, msg, &combined_pk, &pre_session, NULL) == 1);
    CHECK(memcmp(&session_cache, &session_cache2, sizeof(session_cache)) == 0);
    CHECK(memcmp(&sig_template, &sig_template2, sizeof(sig_template)) == 0);
    CHECK(nonce_parity == nonce_parity2);
}

/* Checks that hash initialized by secp256k1_musig_sha256_init_tagged has the
 * expected state. */
void sha256_tag_test(void) {
    char tag[18] = "KeyAgg coefficient";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_tagged;
    unsigned char buf[32];
    unsigned char buf2[32];
    size_t i;

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, (unsigned char *) tag, sizeof(tag));
    secp256k1_sha256_finalize(&sha, buf);
    /* buf = SHA256("KeyAgg coefficient") */

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha, buf, 32);
    /* Is buffer fully consumed? */
    CHECK((sha.bytes & 0x3F) == 0);

    /* Compare with tagged SHA */
    secp256k1_musig_sha256_init_tagged(&sha_tagged);
    for (i = 0; i < 8; i++) {
        CHECK(sha_tagged.s[i] == sha.s[i]);
    }
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha_tagged, buf, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_sha256_finalize(&sha_tagged, buf2);
    CHECK(memcmp(buf, buf2, 32) == 0);
}

/* Attempts to create a signature for the combined public key using given secret
 * keys and pre_session. */
void musig_tweak_test_helper(const secp256k1_xonly_pubkey* combined_pk, const unsigned char *sk0, const unsigned char *sk1, secp256k1_musig_pre_session *pre_session) {
    secp256k1_xonly_pubkey pk[2];
    unsigned char session_id[2][32];
    unsigned char msg[32];
    secp256k1_musig_secnonce secnonce[2];
    unsigned char pubnonce[2][66];
    const unsigned char *pubnonce_ptr[2];
    secp256k1_keypair keypair[2];
    secp256k1_musig_session_cache session_cache;
    secp256k1_musig_template sig_template;
    secp256k1_musig_partial_signature partial_sig[2];
    const secp256k1_musig_partial_signature *partial_sig_ptr[2];
    unsigned char final_sig[64];
    int i;

    for (i = 0; i < 2; i++) {
        pubnonce_ptr[i] = pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        secp256k1_testrand256(session_id[i]);
    }
    CHECK(create_keypair_and_pk(&keypair[0], &pk[0], sk0) == 1);
    CHECK(create_keypair_and_pk(&keypair[1], &pk[1], sk1) == 1);
    secp256k1_testrand256(msg);

    CHECK(secp256k1_musig_session_init(ctx, &secnonce[0], pubnonce[0], session_id[0], sk0, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_session_init(ctx, &secnonce[1], pubnonce[1], session_id[1], sk1, NULL, NULL, NULL) == 1);

    CHECK(secp256k1_musig_process_nonces(ctx, &session_cache, &sig_template, NULL, pubnonce_ptr, 2, msg, combined_pk, pre_session, NULL) == 1);

    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[0], &secnonce[0], &keypair[0], pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[1], &secnonce[1], &keypair[1], pre_session, &session_cache) == 1);

    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[0], pubnonce[0], &pk[0], pre_session, &session_cache) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[1], pubnonce[1], &pk[1], pre_session, &session_cache) == 1);

    CHECK(secp256k1_musig_partial_sig_combine(ctx, final_sig, &sig_template, partial_sig_ptr, 2));
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, combined_pk) == 1);
}

/* In this test we create a combined public key P and a commitment Q = P +
 * hash(P, contract)*G. Then we test that we can sign for both public keys. In
 * order to sign for Q we use the tweak32 argument of partial_sig_combine. */
void musig_tweak_test(secp256k1_scratch_space *scratch) {
    unsigned char sk[2][32];
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    secp256k1_musig_pre_session pre_session_P;
    secp256k1_musig_pre_session pre_session_Q;
    secp256k1_xonly_pubkey P;
    unsigned char P_serialized[32];
    secp256k1_pubkey Q;
    int Q_parity;
    secp256k1_xonly_pubkey Q_xonly;
    unsigned char Q_serialized[32];
    secp256k1_sha256 sha;
    unsigned char contract[32];
    unsigned char ec_commit_tweak[32];
    int i;

    /* Setup */

    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];

        secp256k1_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(NULL, &pk[i], sk[i]) == 1);
    }
    secp256k1_testrand256(contract);

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &P, &pre_session_P, pk_ptr, 2) == 1);

    CHECK(secp256k1_xonly_pubkey_serialize(ctx, P_serialized, &P) == 1);
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, P_serialized, 32);
    secp256k1_sha256_write(&sha, contract, 32);
    secp256k1_sha256_finalize(&sha, ec_commit_tweak);
    pre_session_Q = pre_session_P;
    CHECK(secp256k1_musig_pubkey_tweak_add(ctx, &pre_session_Q, &Q, &P, ec_commit_tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &Q_xonly, &Q_parity, &Q));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, Q_serialized, &Q_xonly));
    /* Check that musig_pubkey_tweak_add produces same result as
     * xonly_pubkey_tweak_add. */
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(ctx, Q_serialized, Q_parity, &P, ec_commit_tweak) == 1);

    /* Test signing for P */
    musig_tweak_test_helper(&P, sk[0], sk[1], &pre_session_P);
    /* Test signing for Q */
    musig_tweak_test_helper(&Q_xonly, sk[0], sk[1], &pre_session_Q);
}

void musig_test_vectors_helper(unsigned char pk_ser[][32], int n_pks, const unsigned char *combined_pk_expected, int has_second_pk, int second_pk_idx) {
    secp256k1_xonly_pubkey *pk = malloc(n_pks * sizeof(*pk));
    const secp256k1_xonly_pubkey **pk_ptr = malloc(n_pks * sizeof(*pk_ptr));
    secp256k1_xonly_pubkey combined_pk;
    unsigned char combined_pk_ser[32];
    secp256k1_musig_pre_session pre_session;
    secp256k1_fe second_pk_x;
    int i;

    for (i = 0; i < n_pks; i++) {
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &pk[i], pk_ser[i]));
        pk_ptr[i] = &pk[i];
    }

    CHECK(secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk, &pre_session, pk_ptr, n_pks) == 1);
    CHECK(secp256k1_fe_set_b32(&second_pk_x, pre_session.second_pk));
    CHECK(secp256k1_fe_is_zero(&second_pk_x) == !has_second_pk);
    if (!secp256k1_fe_is_zero(&second_pk_x)) {
        CHECK(secp256k1_memcmp_var(&pk_ser[second_pk_idx], &pre_session.second_pk, sizeof(pk_ser[second_pk_idx])) == 0);
    }
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, combined_pk_ser, &combined_pk));
    /* TODO: remove when test vectors are not expected to change anymore */
    /* int k, l; */
    /* printf("const unsigned char combined_pk_expected[32] = {\n"); */
    /* for (k = 0; k < 4; k++) { */
    /*     printf("    "); */
    /*     for (l = 0; l < 8; l++) { */
    /*         printf("0x%02X, ", combined_pk_ser[k*8+l]); */
    /*     } */
    /*     printf("\n"); */
    /* } */
    /* printf("};\n"); */
    CHECK(secp256k1_memcmp_var(combined_pk_ser, combined_pk_expected, sizeof(combined_pk_ser)) == 0);
    free(pk);
}

void musig_test_vectors(void) {
    size_t i;
    unsigned char pk_ser_tmp[4][32];
    unsigned char pk_ser[3][32] = {
        /* X1 */
        {
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
            0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
            0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
            0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9
        },
        /* X2 */
        {
            0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
            0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
            0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
            0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59
         },
         /* X3 */
         {
            0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18,
            0x15, 0xC2, 0xF2, 0x4B, 0x4D, 0x80, 0xA8, 0xE3,
            0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7,
            0xAD, 0x33, 0x83, 0x68, 0xD0, 0x38, 0xCA, 0x66
         }
    };
    const unsigned char combined_pk_expected[4][32] = {
        { /* 0 */
            0xEA, 0x06, 0x7B, 0x01, 0x67, 0x24, 0x5A, 0x6F,
            0xED, 0xB1, 0xB1, 0x22, 0xBB, 0x03, 0xAB, 0x7E,
            0x5D, 0x48, 0x6C, 0x81, 0x83, 0x42, 0xE0, 0xE9,
            0xB6, 0x41, 0x79, 0xAD, 0x32, 0x8D, 0x9D, 0x19,
        },
        { /* 1 */
            0x14, 0xE1, 0xF8, 0x3E, 0x9E, 0x25, 0x60, 0xFB,
            0x2A, 0x6C, 0x04, 0x24, 0x55, 0x6C, 0x86, 0x8D,
            0x9F, 0xB4, 0x63, 0x35, 0xD4, 0xF7, 0x8D, 0x22,
            0x7D, 0x5D, 0x1D, 0x3C, 0x89, 0x90, 0x6F, 0x1E,
        },
        { /* 2 */
            0x70, 0x28, 0x8D, 0xF2, 0xB7, 0x60, 0x3D, 0xBE,
            0xA0, 0xC7, 0xB7, 0x41, 0xDD, 0xAA, 0xB9, 0x46,
            0x81, 0x14, 0x4E, 0x0B, 0x19, 0x08, 0x6C, 0x69,
            0xB2, 0x34, 0x89, 0xE4, 0xF5, 0xB7, 0x01, 0x9A,
        },
        { /* 3 */
            0x93, 0xEE, 0xD8, 0x24, 0xF2, 0x3C, 0x5A, 0xE1,
            0xC1, 0x05, 0xE7, 0x31, 0x09, 0x97, 0x3F, 0xCD,
            0x4A, 0xE3, 0x3A, 0x9F, 0xA0, 0x2F, 0x0A, 0xC8,
            0x5A, 0x3E, 0x55, 0x89, 0x07, 0x53, 0xB0, 0x67,
        },
    };

    for (i = 0; i < sizeof(combined_pk_expected)/sizeof(combined_pk_expected[0]); i++) {
        size_t n_pks;
        int has_second_pk;
        int second_pk_idx;
        switch (i) {
            case 0:
                /* [X1, X2, X3] */
                n_pks = 3;
                memcpy(pk_ser_tmp[0], pk_ser[0], sizeof(pk_ser_tmp[0]));
                memcpy(pk_ser_tmp[1], pk_ser[1], sizeof(pk_ser_tmp[1]));
                memcpy(pk_ser_tmp[2], pk_ser[2], sizeof(pk_ser_tmp[2]));
                has_second_pk = 1;
                second_pk_idx = 1;
                break;
            case 1:
                /* [X3, X2, X1] */
                n_pks = 3;
                memcpy(pk_ser_tmp[2], pk_ser[0], sizeof(pk_ser_tmp[0]));
                memcpy(pk_ser_tmp[1], pk_ser[1], sizeof(pk_ser_tmp[1]));
                memcpy(pk_ser_tmp[0], pk_ser[2], sizeof(pk_ser_tmp[2]));
                has_second_pk = 1;
                second_pk_idx = 1;
                break;
            case 2:
                /* [X1, X1, X1] */
                n_pks = 3;
                memcpy(pk_ser_tmp[0], pk_ser[0], sizeof(pk_ser_tmp[0]));
                memcpy(pk_ser_tmp[1], pk_ser[0], sizeof(pk_ser_tmp[1]));
                memcpy(pk_ser_tmp[2], pk_ser[0], sizeof(pk_ser_tmp[2]));
                has_second_pk = 0;
                second_pk_idx = 0; /* unchecked */
                break;
            case 3:
                /* [X1, X1, X2, X2] */
                n_pks = 4;
                memcpy(pk_ser_tmp[0], pk_ser[0], sizeof(pk_ser_tmp[0]));
                memcpy(pk_ser_tmp[1], pk_ser[0], sizeof(pk_ser_tmp[1]));
                memcpy(pk_ser_tmp[2], pk_ser[1], sizeof(pk_ser_tmp[2]));
                memcpy(pk_ser_tmp[3], pk_ser[1], sizeof(pk_ser_tmp[3]));
                has_second_pk = 1;
                second_pk_idx = 3;
                break;
            default:
                CHECK(0);
        }
        musig_test_vectors_helper(pk_ser_tmp, n_pks, combined_pk_expected[i], has_second_pk, second_pk_idx);
    }
}

void run_musig_tests(void) {
    int i;
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    for (i = 0; i < count; i++) {
        musig_simple_test(scratch);
    }
    musig_api_tests(scratch);
    musig_nonce_test();
    for (i = 0; i < count; i++) {
        /* Run multiple times to ensure that pk and nonce have different y
         * parities */
        scriptless_atomic_swap(scratch);
        musig_combiner_test(scratch);
        musig_tweak_test(scratch);
    }
    musig_test_vectors();
    sha256_tag_test();

    secp256k1_scratch_space_destroy(ctx, scratch);
}

#endif
