/**********************************************************************
 * Copyright (c) 2018 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/**
 * This file demonstrates how to use the MuSig module to create a multisignature.
 * Additionally, see the documentation in include/secp256k1_musig.h.
 */

#include <stdio.h>
#include <assert.h>
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 3
 /* Create a key pair and store it in seckey and pubkey */
int create_key(const secp256k1_context* ctx, unsigned char* seckey, secp256k1_pubkey* pubkey) {
    int ret;
    FILE *frand = fopen("/dev/urandom", "r");
    do {
        if (frand == NULL || !fread(seckey, 32, 1, frand)) {
            return 0;
        }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    ret = secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
    return ret;
}

/* Sign a message hash with the given key pairs and store the result in sig */
int sign(const secp256k1_context* ctx, unsigned char seckeys[][32], const secp256k1_pubkey* pubkeys, const unsigned char* msg32, secp256k1_schnorrsig *sig) {
    secp256k1_musig_session musig_session[3];
    unsigned char nonce_commitment[N_SIGNERS][32];
    const unsigned char *nonce_commitment_ptr[N_SIGNERS];
    secp256k1_musig_signer_data signer_data[N_SIGNERS][N_SIGNERS];
    secp256k1_pubkey nonce[N_SIGNERS];
    int i, j;
    secp256k1_musig_partial_signature partial_sig[N_SIGNERS];

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char session_id32[32];
        unsigned char pk_hash[32];
        secp256k1_pubkey combined_pk;

        /* Create combined pubkey and initialize signer data */
        if (!secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk, pk_hash, pubkeys, N_SIGNERS)) {
            return 0;
        }
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_musig_session_initialize. */
        frand = fopen("/dev/urandom", "r");
        if (frand == NULL || !fread(session_id32, 32, 1, frand)) {
            return 0;
        }
        fclose(frand);
        /* Initialize session */
        if (!secp256k1_musig_session_initialize(ctx, &musig_session[i], signer_data[i], nonce_commitment[i], session_id32, msg32, &combined_pk, pk_hash, pubkeys, N_SIGNERS, i, seckeys[i])) {
            return 0;
        }
        nonce_commitment_ptr[i] = nonce_commitment[i];
    }
    /* Communication round 1: Exchange nonce commitments */
    for (i = 0; i < N_SIGNERS; i++) {
        /* Set nonce commitments in the signer data and get the own public nonce */
        if (!secp256k1_musig_session_get_public_nonce(ctx, &musig_session[i], &nonce[i], signer_data[i], nonce_commitment_ptr, N_SIGNERS)) {
            return 0;
        }
    }
    /* Communication round 2: Exchange nonces */
    for (i = 0; i < N_SIGNERS; i++) {
        for (j = 0; j < N_SIGNERS; j++) {
            if (!secp256k1_musig_set_nonce(ctx, &signer_data[i][j], &nonce[j])) {
                /* Signer j's nonce does not match the nonce commitment. Wait
                 * until the correct nonce is received or restart the protocol
                 * (with a different session ID of course). */
                return 0;
            }
        }
        if (!secp256k1_musig_session_combine_nonces(ctx, &musig_session[i], NULL, signer_data[i], N_SIGNERS, NULL)) {
            return 0;
        }
    }
    for (i = 0; i < N_SIGNERS; i++) {
        if (!secp256k1_musig_partial_sign(ctx, &musig_session[i], &partial_sig[i])) {
            return 0;
        }
    }
    /* Communication round 3: Exchange partial signatures */
    for (i = 0; i < N_SIGNERS; i++) {
        for (j = 0; j < N_SIGNERS; j++) {
            if (!secp256k1_musig_partial_sig_verify(ctx, &musig_session[i], &partial_sig[j], &signer_data[i][j])) {
                return 0;
            }
        }
    }
    return secp256k1_musig_partial_sig_combine(ctx, &musig_session[0], sig, partial_sig, N_SIGNERS);
}

 int main(void) {
    secp256k1_context* ctx;
    int i;
    unsigned char seckeys[N_SIGNERS][32];
    secp256k1_pubkey pubkeys[N_SIGNERS];
    secp256k1_pubkey combined_pk;
    unsigned char msg[32] = "this_should_actually_be_msg_hash";
    secp256k1_schnorrsig sig;

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    printf("Creating key pairs......");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!create_key(ctx, seckeys[i], &pubkeys[i])) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");
    printf("Combining public keys...");
    if (!secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk, NULL, pubkeys, N_SIGNERS)) {
        printf("FAILED\n");
        return 0;
    }
    printf("ok\n");
    printf("Signing message.........");
    if (!sign(ctx, seckeys, pubkeys, msg, &sig)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying signature.....");
    if (!secp256k1_schnorrsig_verify(ctx, &sig, msg, &combined_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    secp256k1_context_destroy(ctx);
    return 0;
}

