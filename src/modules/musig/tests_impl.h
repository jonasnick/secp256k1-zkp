/**********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_TESTS_
#define _SECP256K1_MODULE_MUSIG_TESTS_

#include "secp256k1_musig.h"

void musig_api_tests(secp256k1_scratch_space *scratch) {
    unsigned char sk1[32];
    unsigned char sk2[32];
    unsigned char sk3[32];
    unsigned char msg[32];
    unsigned char secnon1[32];
    unsigned char secnon2[32];
    unsigned char secnon3[32];
    unsigned char secnon_tmp[32];
    unsigned char zeros[32] = { 0 };
    unsigned char noncom1[32];
    unsigned char noncom2[32];
    unsigned char noncom3[32];
    unsigned char in33[33];
    unsigned char out33[33];
    secp256k1_pubkey pk[3];
    secp256k1_pubkey pubnon1;
    secp256k1_pubkey pubnon2;
    secp256k1_pubkey pubnon3;
    secp256k1_pubkey combined_pk;
    secp256k1_musig_config musig_config;
    secp256k1_schnorrsig sig;
    secp256k1_musig_partial_signature partial_sig[3];
    secp256k1_musig_validation_aux aux;

    unsigned char commit[32];
    const secp256k1_pubkey *pkptr = &pk[0];
    secp256k1_musig_signer_data signer_data[3];

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    secp256k1_rand256(sk1);
    secp256k1_rand256(sk2);
    secp256k1_rand256(sk3);
    secp256k1_rand256(msg);
    secp256k1_rand256(commit);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[0], sk1) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[1], sk2) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[2], sk3) == 1);

    /** main test body **/
    /** MuSig configuration **/
    ecount = 0;
    CHECK(secp256k1_musig_init(none, scratch, &musig_config, pkptr, 3) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_init(sign, scratch, &musig_config, pkptr, 3) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_init(vrfy, NULL, &musig_config, pkptr, 3) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_init(vrfy, scratch, NULL, pkptr, 3) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_init(vrfy, scratch, &musig_config, NULL, 3) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_init(vrfy, scratch, &musig_config, pkptr, 0) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_musig_init(vrfy, scratch, &musig_config, pkptr, 3) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_pubkey(none, NULL, &musig_config) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey(none, &combined_pk, NULL) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_pubkey(none, &combined_pk, &musig_config) == 1);

    /*
     * For the API tests we will only generate `signer_data` once and use it for all signers,
     * since it contains only public data that should be the same for all signers.
     */
    ecount = 0;
    CHECK(secp256k1_musig_multisig_generate_nonce(none, secnon1, &pubnon1, noncom1, sk1, msg, commit) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, sk1, msg, commit) == 1);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(vrfy, secnon1, &pubnon1, noncom1, sk1, msg, commit) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, NULL, &pubnon1, noncom1, sk1, msg, commit) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, NULL, noncom1, sk1, msg, commit) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, NULL, sk1, msg, commit) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, NULL, msg, commit) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, sk1, NULL, commit) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, sk1, msg, NULL) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon1, &pubnon1, noncom1, sk1, msg, commit) == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon2, &pubnon2, noncom2, sk2, msg, commit) == 1);
    CHECK(secp256k1_musig_multisig_generate_nonce(sign, secnon3, &pubnon3, noncom3, sk3, msg, commit) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[0], &musig_config, 0, noncom1) == 1);
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[0], NULL, 0, noncom1) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[1], &musig_config, 1, noncom2) == 1);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_signer_data_initialize(none, &signer_data[2], &musig_config, 2, noncom3) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[0], &pubnon1) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_set_nonce(none, NULL, &pubnon1) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[0], NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[1], &pubnon1) == 0);
    CHECK(ecount == 2);

    CHECK(secp256k1_musig_set_nonce(none, &signer_data[0], &pubnon1) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[1], &pubnon2) == 1);
    CHECK(secp256k1_musig_set_nonce(none, &signer_data[2], &pubnon3) == 1);

    memset(in33, 1, 33);
    ecount = 0;
    CHECK(secp256k1_musig_partial_signature_parse(none, NULL, in33) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_signature_parse(none, &partial_sig[0], in33) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_signature_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_signature_serialize(none, out33, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_signature_serialize(none, out33, &partial_sig[0]) == 1);
    CHECK(memcmp(in33, out33, 33) == 0);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sign(none, scratch, &partial_sig[0], &aux, secnon1, &musig_config, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 1);
    /* Use temporary secnon, because it will be zeroed during a successful partial sign */
    memcpy(secnon_tmp, secnon1, 32);
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig[0], &aux, secnon_tmp, &musig_config, sk1, msg, signer_data, 0, NULL) == 1);
    CHECK(secp256k1_musig_partial_sign(vrfy, NULL, &partial_sig[0], &aux, secnon1, &musig_config, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, NULL, &aux, secnon1, &musig_config, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], NULL, secnon1, &musig_config, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, secnon1, NULL, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, secnon1, &musig_config, NULL, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, secnon1, &musig_config, sk1, NULL, signer_data, 0, NULL) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, NULL, &musig_config, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, secnon1, &musig_config, sk1, msg, NULL, 0, NULL) == 0);
    CHECK(ecount == 9);

    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, secnon1, &musig_config, sk1, msg, signer_data, 0, NULL) == 1);
    /* The nonce has been zeroed */
    CHECK(memcmp(secnon1, zeros, 32) == 0);
    /* And signig with a zero nonce fails */
    CHECK(secp256k1_musig_partial_sign(vrfy, scratch, &partial_sig[0], &aux, secnon1, &musig_config, sk1, msg, signer_data, 0, NULL) == 0);
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig[1], &aux, secnon2, &musig_config, sk2, msg, signer_data, 1, NULL) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig[2], &aux, secnon3, &musig_config, sk3, msg, signer_data, 2, NULL) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_verify(none, &partial_sig[0], &signer_data[0], &aux) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_verify(sign, &partial_sig[0], &signer_data[0], &aux) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &signer_data[0], &aux) == 1);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &signer_data[1], &aux) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &signer_data[1], &aux) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[2], &signer_data[2], &aux) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, &musig_config, partial_sig, &aux) == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, NULL, &musig_config, partial_sig, &aux) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, &musig_config, NULL, &aux) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, &musig_config, partial_sig, NULL) == 0);
    CHECK(ecount == 3);

    CHECK(secp256k1_musig_partial_sig_combine(none, &sig, &musig_config, partial_sig, &aux) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, &sig, msg, &combined_pk) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_config_destroy(none, NULL) == 0);
    CHECK(ecount == 1);

    /** cleanup **/
    CHECK(secp256k1_musig_config_destroy(none, &musig_config));
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

void musig_simple_test(secp256k1_scratch_space *scratch) {
    unsigned char sk1[32];
    unsigned char msg[32];
    secp256k1_musig_signer_data signer_data[1];
    unsigned char rngseed[32];
    secp256k1_pubkey pk[3];
    secp256k1_pubkey pubnon1;
    unsigned char noncom1[32];
    unsigned char secnon1[32];
    const secp256k1_pubkey *pkptr = &pk[0];
    secp256k1_musig_validation_aux aux;
    secp256k1_musig_partial_signature partial_sig[1];
    secp256k1_musig_config musig_config_untweaked;

    secp256k1_rand256(sk1);
    secp256k1_rand256(msg);
    secp256k1_rand256(rngseed);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk[0], sk1) == 1);

    CHECK(secp256k1_musig_init(ctx, scratch, &musig_config_untweaked, pkptr, 1, 1, NULL, NULL, NULL) == 1);                                                                                                       
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon1, &pubnon1, noncom1, sk1, msg, rngseed) == 1);                                                                                                      


    CHECK(secp256k1_musig_signer_data_initialize(ctx, &signer_data[0], &musig_config_untweaked.tweaked_pks[0], noncom1));                                                                                         
    CHECK(secp256k1_musig_set_nonce(ctx, &signer_data[0], &pubnon1) == 1);
    print_pubkey(ctx, &musig_config_untweaked.combined_pk);
    print_pubkey(ctx, &musig_config_untweaked.combined_pk_untweaked);

    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig[0], &aux, secnon1, &musig_config_untweaked, sk1, msg, signer_data, 0, NULL) == 1);                                                              
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[0], &signer_data[0], &aux) == 1);
}

void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    /* Thoughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    secp256k1_schnorrsig final_sig_a;
    secp256k1_schnorrsig final_sig_b;
    secp256k1_musig_partial_signature partial_sig_a[2];
    secp256k1_musig_partial_signature partial_sig_b[2];
    secp256k1_musig_partial_signature adaptor_sig_a;
    secp256k1_musig_partial_signature adaptor_sig_b;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor_a;
    secp256k1_pubkey pub_adaptor_b;
    secp256k1_musig_validation_aux aux_a;
    secp256k1_musig_validation_aux aux_b;

    unsigned char seckey_a[2][32];
    unsigned char seckey_b[2][32];
    secp256k1_pubkey pk_a[2];
    secp256k1_pubkey pk_b[2];
    secp256k1_pubkey combine_pk_a;
    secp256k1_pubkey combine_pk_b;
    secp256k1_musig_config musig_config_a;
    secp256k1_musig_config musig_config_b;
    unsigned char secnon_a[2][32];
    unsigned char secnon_b[2][32];
    unsigned char noncommit_a[2][32];
    unsigned char noncommit_b[2][32];
    secp256k1_pubkey pubnon_a[2];
    secp256k1_pubkey pubnon_b[2];
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

    CHECK(secp256k1_musig_init(ctx, scratch, &musig_config_a, pk_a, 2));
    CHECK(secp256k1_musig_init(ctx, scratch, &musig_config_b, pk_b, 2));

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_a[0], &pubnon_a[0], noncommit_a[0], seckey_a[0], msg32_a, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_a[1], &pubnon_a[1], noncommit_a[1], seckey_a[1], msg32_a, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_b[0], &pubnon_b[0], noncommit_b[0], seckey_b[0], msg32_b, seed));
    CHECK(secp256k1_musig_multisig_generate_nonce(ctx, secnon_b[1], &pubnon_b[1], noncommit_b[1], seckey_b[1], msg32_b, seed));

    secp256k1_musig_signer_data_initialize(ctx, &data_a[0], &musig_config_a, 0, noncommit_a[0]);
    secp256k1_musig_signer_data_initialize(ctx, &data_a[1], &musig_config_a, 1, noncommit_a[1]);
    secp256k1_musig_signer_data_initialize(ctx, &data_b[0], &musig_config_b, 0, noncommit_b[0]);
    secp256k1_musig_signer_data_initialize(ctx, &data_b[1], &musig_config_b, 1, noncommit_b[1]);
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[0], &pubnon_a[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_a[1], &pubnon_a[1]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[0], &pubnon_b[0]));
    CHECK(secp256k1_musig_set_nonce(ctx, &data_b[1], &pubnon_b[1]));

    /* Step 2: Signer 0 produces adaptor signatures */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &adaptor_sig_a, &aux_a, secnon_a[0], &musig_config_a, seckey_a[0], msg32_a, data_a, 0, sec_adaptor));
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &adaptor_sig_b, &aux_b, secnon_b[0], &musig_config_b, seckey_b[0], msg32_b, data_b, 0, sec_adaptor));

    /* Step 3: Signer 1 receives adaptor signatures, checks that they used the same public adaptor, and signs to send B-coins */
    CHECK(secp256k1_musig_adaptor_signature_extract(ctx, &pub_adaptor_a, &adaptor_sig_a, &data_a[0], &aux_a));
    CHECK(secp256k1_musig_adaptor_signature_extract(ctx, &pub_adaptor_b, &adaptor_sig_b, &data_b[0], &aux_b));
    CHECK(memcmp(&pub_adaptor_a, &pub_adaptor_b, sizeof(pub_adaptor_a)) == 0); /* TODO the API says we're not allowed to compare pubkeys like this, but c'mon */
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_b[1], &aux_b, secnon_b[1], &musig_config_b, seckey_b[1], msg32_b, data_b, 1, NULL));

    /* Step 4: Signer 0 signs to take B-coins, combines signatures and publishes */
    CHECK(secp256k1_musig_adaptor_signature_adapt(ctx, &partial_sig_b[0], &adaptor_sig_b, sec_adaptor));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &final_sig_b, &musig_config_b, partial_sig_b, &aux_b) == 1);
    CHECK(secp256k1_musig_pubkey(ctx, &combine_pk_b, &musig_config_b));
    CHECK(secp256k1_schnorrsig_verify(ctx, &final_sig_b, msg32_b, &combine_pk_b) == 1);

    /* Step 5: Signer 1 extracts secret from published signature, applies it to other adaptor signature, and takes A-coins */
    CHECK(secp256k1_musig_adaptor_signature_extract_secret(ctx, sec_adaptor_extracted, &musig_config_b, &final_sig_b, &adaptor_sig_b, &partial_sig_b[1]) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_adaptor_signature_adapt(ctx, &partial_sig_a[0], &adaptor_sig_a, sec_adaptor_extracted));
    CHECK(secp256k1_musig_partial_sign(ctx, scratch, &partial_sig_a[1], &aux_a, secnon_a[1], &musig_config_a, seckey_a[1], msg32_a, data_a, 1, NULL));
    CHECK(secp256k1_musig_partial_sig_combine(ctx, &final_sig_a, &musig_config_a, partial_sig_a, &aux_a) == 1);
    CHECK(secp256k1_musig_pubkey(ctx, &combine_pk_a, &musig_config_a));
    CHECK(secp256k1_schnorrsig_verify(ctx, &final_sig_a, msg32_a, &combine_pk_a) == 1);

    CHECK(secp256k1_musig_config_destroy(ctx, &musig_config_a));
    CHECK(secp256k1_musig_config_destroy(ctx, &musig_config_b));
}

void run_musig_tests(void) {
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    musig_api_tests(scratch);
    musig_simple_test(scratch);
    scriptless_atomic_swap(scratch);

    secp256k1_scratch_space_destroy(scratch);
}

#endif
