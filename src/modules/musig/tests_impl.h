/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

void musig_api_tests(secp256k1_scratch_space *scratch) {
    secp256k1_musig_session session[2];
    secp256k1_musig_session observer_session;
    secp256k1_musig_signer_data signer0[2];
    secp256k1_musig_signer_data signer1[2];
    secp256k1_musig_signer_data signer_observer[2];
    secp256k1_musig_partial_signature partial_sig[2];
    secp256k1_musig_partial_signature partial_sig_adapted[2];
    secp256k1_schnorrsig final_sig;
    secp256k1_schnorrsig final_sig_cmp;

    unsigned char buf[32];
    unsigned char sk[2][32];
    unsigned char session_id[2][32];
    unsigned char nonce_commitment[2][32];
    int nonce_is_negated;
    const unsigned char *ncs[2];
    unsigned char msg[32];
    secp256k1_pubkey combined_pk;
    unsigned char pk_hash[32];
    secp256k1_pubkey pk[2];

    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;

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

    secp256k1_rand256(session_id[0]);
    secp256k1_rand256(session_id[1]);
    secp256k1_rand256(sk[0]);
    secp256k1_rand256(sk[1]);
    secp256k1_rand256(msg);
    secp256k1_rand256(sec_adaptor);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[0], sk[0]) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[1], sk[1]) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);

    /** main test body **/

    /* Key combination */
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_combine(none, scratch, &combined_pk, pk_hash, pk, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey_combine(sign, scratch, &combined_pk, pk_hash, pk, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, pk, 2) == 1);
    CHECK(ecount == 2);
    /* pubkey_combine does not require a scratch space */
    CHECK(secp256k1_musig_pubkey_combine(vrfy, NULL, &combined_pk, pk_hash, pk, 2) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, NULL, pk_hash, pk, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, NULL, pk, 2) == 1);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, NULL, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, pk, 0) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, NULL, 0) == 0);
    CHECK(ecount == 6);

    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, pk, 2) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, pk, 2) == 1);
    CHECK(secp256k1_musig_pubkey_combine(vrfy, scratch, &combined_pk, pk_hash, pk, 2) == 1);

    /** Session creation **/
    ecount = 0;
    CHECK(secp256k1_musig_session_initialize(none, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_session_initialize(vrfy, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_initialize(sign, NULL, signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], NULL, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, NULL, session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], NULL, msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], NULL, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 1);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, NULL, pk_hash, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, NULL, pk, 2, 0, sk[0]) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, NULL, 2, 0, sk[0]) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 0, 0, sk[0]) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, NULL) == 0);
    CHECK(ecount == 10);

    {
        secp256k1_musig_session session_without_msg;
        CHECK(secp256k1_musig_session_initialize(sign, &session_without_msg, signer0, nonce_commitment[0], session_id[0], NULL, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 1);
        CHECK(secp256k1_musig_session_set_msg(none, &session_without_msg, msg) == 1);
        CHECK(secp256k1_musig_session_set_msg(none, &session_without_msg, msg) == 0);
    }
    CHECK(secp256k1_musig_session_initialize(sign, &session[0], signer0, nonce_commitment[0], session_id[0], msg, &combined_pk, pk_hash, pk, 2, 0, sk[0]) == 1);
    CHECK(secp256k1_musig_session_initialize(sign, &session[1], signer1, nonce_commitment[1], session_id[1], msg, &combined_pk, pk_hash, pk, 2, 1, sk[1]) == 1);
    ncs[0] = nonce_commitment[0];
    ncs[1] = nonce_commitment[1];

    ecount = 0;
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, &combined_pk, pk_hash, pk, ncs, 2) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_session_initialize_public(none, NULL, signer_observer, msg, &combined_pk, pk_hash, pk, ncs, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, NULL, &combined_pk, pk_hash, pk, ncs, 2) == 1);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, NULL, pk_hash, pk, ncs, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, &combined_pk, NULL, pk, ncs, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, &combined_pk, pk_hash, NULL, ncs, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, &combined_pk, pk_hash, pk, NULL, 2) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, &combined_pk, pk_hash, pk, ncs, 0) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_session_initialize_public(none, &observer_session, signer_observer, msg, &combined_pk, pk_hash, pk, ncs, 2) == 1);

    /** Signing step 0 -- exchange nonce commitments */
    ecount = 0;
    {
        secp256k1_pubkey nonce;

        /* Can obtain public nonce after commitments have been exchanged; still can't sign */
        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], &nonce, signer0, ncs, 2) == 1);
        CHECK(secp256k1_musig_partial_sign(none, &session[0], &partial_sig[0]) == 0);
        CHECK(ecount == 0);
    }

    /** Signing step 1 -- exchange nonces */
    ecount = 0;
    {
        secp256k1_pubkey public_nonce[3];

        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], &public_nonce[0], signer0, ncs, 2) == 1);
        CHECK(ecount == 0);
        CHECK(secp256k1_musig_session_get_public_nonce(none, NULL, &public_nonce[0], signer0, ncs, 2) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], NULL, signer0, ncs, 2) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], &public_nonce[0], NULL, ncs, 2) == 0);
        CHECK(ecount == 3);
        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], &public_nonce[0], signer0, NULL, 2) == 0);
        CHECK(ecount == 4);
        /* Number of commitments and number of signers are different */
        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], &public_nonce[0], signer0, ncs, 1) == 0);
        CHECK(ecount == 4);

        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[0], &public_nonce[0], signer0, ncs, 2) == 1);
        CHECK(secp256k1_musig_session_get_public_nonce(none, &session[1], &public_nonce[1], signer1, ncs, 2) == 1);

        CHECK(secp256k1_musig_set_nonce(none, &signer0[0], &public_nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer0[1], &public_nonce[0]) == 0);
        CHECK(secp256k1_musig_set_nonce(none, &signer0[1], &public_nonce[1]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer0[1], &public_nonce[1]) == 1);
        CHECK(ecount == 4);

        CHECK(secp256k1_musig_set_nonce(none, NULL, &public_nonce[0]) == 0);
        CHECK(ecount == 5);
        CHECK(secp256k1_musig_set_nonce(none, &signer1[0], NULL) == 0);
        CHECK(ecount == 6);

        CHECK(secp256k1_musig_set_nonce(none, &signer1[0], &public_nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer1[1], &public_nonce[1]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer_observer[0], &public_nonce[0]) == 1);
        CHECK(secp256k1_musig_set_nonce(none, &signer_observer[1], &public_nonce[1]) == 1);

        ecount = 0;
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], &nonce_is_negated, signer0, 2, &adaptor) == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, NULL, &nonce_is_negated, signer0, 2, &adaptor) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], NULL, signer0, 2, &adaptor) == 1);
        CHECK(ecount == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], &nonce_is_negated, NULL, 2, &adaptor) == 0);
        CHECK(ecount == 2);
        /* Number of signers differs from number during intialization */
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], &nonce_is_negated, signer0, 1, &adaptor) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], &nonce_is_negated, signer0, 2, NULL) == 1);

        CHECK(secp256k1_musig_session_combine_nonces(none, &session[0], &nonce_is_negated, signer0, 2, &adaptor) == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, &session[1], &nonce_is_negated, signer0, 2, &adaptor) == 1);
        CHECK(secp256k1_musig_session_combine_nonces(none, &observer_session, &nonce_is_negated, signer_observer, 2, &adaptor) == 1);
    }

    /** Signing step 2 -- partial signatures */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sign(none, &session[0], &partial_sig[0]) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_partial_sign(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sign(none, &session[0], NULL) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_partial_sign(none, &session[0], &partial_sig[0]) == 1);
    CHECK(secp256k1_musig_partial_sign(none, &session[1], &partial_sig[1]) == 1);
    /* observer can't sign */
    CHECK(secp256k1_musig_partial_sign(none, &observer_session, &partial_sig[2]) == 0);
    CHECK(ecount == 2);

    ecount = 0;
    CHECK(secp256k1_musig_partial_signature_serialize(none, buf, &partial_sig[0]) == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, buf, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], buf) == 1);
    CHECK(secp256k1_musig_partial_signature_parse(none, NULL, buf) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 4);

    /** Partial signature verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_verify(none, &session[0], &partial_sig[0], &signer0[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_verify(sign, &session[0], &partial_sig[0], &signer0[0]) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[0], &partial_sig[0], &signer0[0]) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[0], &partial_sig[1], &signer0[0]) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_partial_sig_verify(vrfy, NULL, &partial_sig[0], &signer0[0]) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[0], NULL, &signer0[0]) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[0], &partial_sig[0], NULL) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[0], &partial_sig[0], &signer0[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[1], &partial_sig[0], &signer1[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[0], &partial_sig[1], &signer0[1]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &session[1], &partial_sig[1], &signer1[1]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &observer_session, &partial_sig[0], &signer_observer[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &observer_session, &partial_sig[1], &signer_observer[1]) == 1);
    CHECK(ecount == 5);

    /** Adaptor signature verification */
    memcpy(&partial_sig_adapted[1], &partial_sig[1], sizeof(partial_sig_adapted[1]));
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], &partial_sig[0], sec_adaptor, nonce_is_negated) == 1);
    CHECK(secp256k1_musig_partial_sig_adapt(none, NULL, &partial_sig[0], sec_adaptor, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], NULL, sec_adaptor, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_adapt(none, &partial_sig_adapted[0], &partial_sig[0], NULL, 0) == 0);
    CHECK(ecount == 3);

    /** Signing combining and verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], &final_sig, partial_sig_adapted, 2) == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], &final_sig_cmp, partial_sig_adapted, 2) == 1);
    CHECK(memcmp(&final_sig, &final_sig_cmp, sizeof(final_sig)) == 0);
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], &final_sig_cmp, partial_sig_adapted, 2) == 1);
    CHECK(memcmp(&final_sig, &final_sig_cmp, sizeof(final_sig)) == 0);

    CHECK(secp256k1_musig_partial_sig_combine(none, NULL, &final_sig, partial_sig_adapted, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], NULL, partial_sig_adapted, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], &final_sig, NULL, 2) == 0);
    CHECK(ecount == 3);
    /* Wrong number of partial sigs */
    CHECK(secp256k1_musig_partial_sig_combine(none, &session[0], &final_sig, partial_sig_adapted, 1) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_schnorrsig_verify(vrfy, &final_sig, msg, &combined_pk) == 1);

    /** Secret adaptor can be extracted from signature */
    ecount = 0;
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, partial_sig, 2, nonce_is_negated) == 1);
    CHECK(memcmp(sec_adaptor, sec_adaptor1, 32) == 0);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, NULL, &final_sig, partial_sig, 2, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, NULL, partial_sig, 2, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, NULL, 2, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, partial_sig, 0, 0) == 1);
    CHECK(secp256k1_musig_extract_secret_adaptor(none, sec_adaptor1, &final_sig, partial_sig, 2, 1) == 1);

    /** cleanup **/
    memset(&session, 0, sizeof(session));
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
}

void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    /* Thoughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    secp256k1_schnorrsig final_sig_a;
    secp256k1_schnorrsig final_sig_b;
    secp256k1_musig_partial_signature partial_sig_a[2];
    secp256k1_musig_partial_signature partial_sig_b_adapted[2];
    secp256k1_musig_partial_signature partial_sig_b[2];
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor;

    unsigned char seckey_a[2][32];
    unsigned char seckey_b[2][32];
    secp256k1_pubkey pk_a[2];
    secp256k1_pubkey pk_b[2];
    unsigned char pk_hash_a[32];
    unsigned char pk_hash_b[32];
    secp256k1_pubkey combined_pk_a;
    secp256k1_pubkey combined_pk_b;
    secp256k1_musig_session musig_session_a[2];
    secp256k1_musig_session musig_session_b[2];
    unsigned char noncommit_a[2][32];
    unsigned char noncommit_b[2][32];
    const unsigned char *noncommit_a_ptr[2];
    const unsigned char *noncommit_b_ptr[2];
    secp256k1_pubkey pubnon_a[2];
    secp256k1_pubkey pubnon_b[2];
    int nonce_is_negated_a;
    int nonce_is_negated_b;
    secp256k1_musig_signer_data data_a[2];
    secp256k1_musig_signer_data data_b[2];

    const unsigned char seed[32] = "still tired of choosing seeds...";
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";

    /* Step 1: key setup */
    secp256k1_rand256(seckey_a[0]);
    secp256k1_rand256(seckey_a[1]);
    secp256k1_rand256(seckey_b[0]);
    secp256k1_rand256(seckey_b[1]);
    secp256k1_rand256(sec_adaptor);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_a[0], seckey_a[0]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_a[1], seckey_a[1]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_b[0], seckey_b[0]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk_b[1], seckey_b[1]));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pub_adaptor, sec_adaptor));

    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk_a, pk_hash_a, pk_a, 2));
    CHECK(secp256k1_musig_pubkey_combine(ctx, scratch, &combined_pk_b, pk_hash_b, pk_b, 2));

    CHECK(secp256k1_musig_session_initialize(ctx, &musig_session_a[0], data_a, noncommit_a[0], seed, msg32_a, &combined_pk_a, pk_hash_a, pk_a, 2, 0, seckey_a[0]));
    CHECK(secp256k1_musig_session_initialize(ctx, &musig_session_a[1], data_a, noncommit_a[1], seed, msg32_a, &combined_pk_a, pk_hash_a, pk_a, 2, 1, seckey_a[1]));
    noncommit_a_ptr[0] = noncommit_a[0];
    noncommit_a_ptr[1] = noncommit_a[1];

    CHECK(secp256k1_musig_session_initialize(ctx, &musig_session_b[0], data_b, noncommit_b[0], seed, msg32_b, &combined_pk_b, pk_hash_b, pk_b, 2, 0, seckey_b[0]));
    CHECK(secp256k1_musig_session_initialize(ctx, &musig_session_b[1], data_b, noncommit_b[1], seed, msg32_b, &combined_pk_b, pk_hash_b, pk_b, 2, 1, seckey_b[1]));
    noncommit_b_ptr[0] = noncommit_b[0];
    noncommit_b_ptr[1] = noncommit_b[1];

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_a[0], &pubnon_a[0], data_a, noncommit_a_ptr, 2));
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_a[1], &pubnon_a[1], data_a, noncommit_a_ptr, 2));
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_b[0], &pubnon_b[0], data_b, noncommit_b_ptr, 2));
    CHECK(secp256k1_musig_session_get_public_nonce(ctx, &musig_session_b[1], &pubnon_b[1], data_b, noncommit_b_ptr, 2));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[0], &pubnon_a[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[1], &pubnon_a[1]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[0], &pubnon_b[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[1], &pubnon_b[1]));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_a[0], &nonce_is_negated_a, data_a, 2, &pub_adaptor));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_a[1], NULL, data_a, 2, &pub_adaptor));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_b[0], &nonce_is_negated_b, data_b, 2, &pub_adaptor));
    CHECK(secp256k1_musig_session_combine_nonces(ctx, &musig_session_b[1], NULL, data_b, 2, &pub_adaptor));

    /* Step 2: Signer 0 produces adaptor signatures */
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_a[0], &partial_sig_a[0]));
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_b[0], &partial_sig_b[0]));

    /* Step 3: Signer 1 receives adaptor signatures and signs to send B-coins */
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_b[1], &partial_sig_b[1]));
    memcpy(&partial_sig_b_adapted[1], &partial_sig_b[1], sizeof(partial_sig_b_adapted[1]));

    /* Step 4: Signer 0 signs to take B-coins, combines signatures and publishes */
    CHECK(secp256k1_musig_partial_sig_adapt(ctx, &partial_sig_b_adapted[0], &partial_sig_b[0], sec_adaptor, nonce_is_negated_b));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &musig_session_b[0], &final_sig_b, partial_sig_b_adapted, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, &final_sig_b, msg32_b, &combined_pk_b) == 1);

    /* Step 5: Signer 1 extracts secret from published signature, applies it to other adaptor signature, and takes A-coins */
    CHECK(secp256k1_musig_extract_secret_adaptor(ctx, sec_adaptor_extracted, &final_sig_b, partial_sig_b, 2, nonce_is_negated_b) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_partial_sig_adapt(ctx, &partial_sig_a[0], &partial_sig_a[0], sec_adaptor_extracted, nonce_is_negated_a));
    CHECK(secp256k1_musig_partial_sign(ctx, &musig_session_a[1], &partial_sig_a[1]));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &musig_session_a[1], &final_sig_a, partial_sig_a, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, &final_sig_a, msg32_a, &combined_pk_a) == 1);
}

void run_musig_tests(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    musig_api_tests(scratch);
    scriptless_atomic_swap(scratch);

    secp256k1_scratch_space_destroy(scratch);
}

#endif
