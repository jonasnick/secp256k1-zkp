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

struct signer_secrets_t {
    secp256k1_keypair keypair;
    secp256k1_musig_secnonce secnonce;
};

struct signer_t {
    secp256k1_xonly_pubkey pubkey;
    unsigned char pubnonce[66];
    secp256k1_musig_partial_signature partial_sig;
};

 /* Number of public keys involved in creating the aggregate signature */
#define N_SIGNERS 3
 /* Create a key pair and store it in seckey and pubkey */
int create_keypair(const secp256k1_context* ctx, struct signer_secrets_t *signer_secrets, struct signer_t *signer) {
    int ret;
    unsigned char seckey[32];
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL) {
        return 0;
    }
    do {
        if(!fread(seckey, sizeof(seckey), 1, frand)) {
             fclose(frand);
             return 0;
         }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
    fclose(frand);
    ret = secp256k1_keypair_create(ctx, &signer_secrets->keypair, seckey);
    ret &= secp256k1_keypair_xonly_pub(ctx, &signer->pubkey, NULL, &signer_secrets->keypair);

    return ret;
}

/* Sign a message hash with the given key pairs and store the result in sig */
int sign(const secp256k1_context* ctx, struct signer_secrets_t *signer_secrets, struct signer_t *signer, const unsigned char* msg32, unsigned char *sig64) {
    int i;
    const secp256k1_xonly_pubkey *pubkeys[N_SIGNERS];
    const unsigned char *pubnonces[N_SIGNERS];
    const secp256k1_musig_partial_signature *partial_sigs[N_SIGNERS];
    /* The same for all signers */
    secp256k1_musig_pre_session pre_session;
    secp256k1_musig_session_cache session_cache;
    secp256k1_musig_template sig_template;

    for (i = 0; i < N_SIGNERS; i++) {
        FILE *frand;
        unsigned char seckey[32];
        unsigned char session_id[32];
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_musig_session_init. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        frand = fopen("/dev/urandom", "r");
        if(frand == NULL) {
            return 0;
        }
        if (!fread(session_id, 32, 1, frand)) {
            fclose(frand);
            return 0;
        }
        fclose(frand);
        if (!secp256k1_keypair_sec(ctx, seckey, &signer_secrets[i].keypair)) {
            return 0;
        }
        /* Initialize session and create secret nonce for signing and public
         * nonce to send to the other signers. */
        if (!secp256k1_musig_session_init(ctx, &signer_secrets[i].secnonce, signer[i].pubnonce, session_id, seckey, msg32, NULL, NULL)) {
            return 0;
        }
        pubkeys[i] = &signer[i].pubkey;
        pubnonces[i] = signer[i].pubnonce;
    }
    /* Communication round 1: Exchange nonces */
    for (i = 0; i < N_SIGNERS; i++) {
        secp256k1_xonly_pubkey combined_pk;

        /* Create combined pubkey and initialize signer data */
        if (!secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk, &pre_session, pubkeys, N_SIGNERS)) {
            return 0;
        }
        if(!secp256k1_musig_process_nonces(ctx, &session_cache, &sig_template, NULL, pubnonces, N_SIGNERS, msg32, &combined_pk, &pre_session, NULL)) {
            return 0;
        }
        /* partial_sign will clear the secnonce by setting it 0. That's because
         * you must _never_ reuse the secnonce (or use the same session_id to
         * create a secnonce). If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!secp256k1_musig_partial_sign(ctx, &signer[i].partial_sig, &signer_secrets[i].secnonce, &signer_secrets[i].keypair, &pre_session, &session_cache)) {
            return 0;
        }
        partial_sigs[i] = &signer[i].partial_sig;
    }
    /* Communication round 2: Exchange partial signatures */
    for (i = 0; i < N_SIGNERS; i++) {
        /* To check whether signing was successful, it suffices to either verify
         * the combined signature with the combined public key using
         * secp256k1_schnorrsig_verify, or verify all partial signatures of all
         * signers individually. Verifying the combined signature is cheaper but
         * verifying the individual partial signatures has the advantage that it
         * can be used to determine which of the partial signatures are invalid
         * (if any), i.e., which of the partial signatures cause the combined
         * signature to be invalid and thus the protocol run to fail. It's also
         * fine to first verify the combined sig, and only verify the individual
         * sigs if it does not work.
         */
        if (!secp256k1_musig_partial_sig_verify(ctx, &signer[i].partial_sig, signer[i].pubnonce, &signer[i].pubkey, &pre_session, &session_cache)) {
            return 0;
        }
    }
    return secp256k1_musig_partial_sig_combine(ctx, sig64, &sig_template, partial_sigs, N_SIGNERS);
}

 int main(void) {
    secp256k1_context* ctx;
    int i;
    struct signer_secrets_t signer_secrets[N_SIGNERS];
    struct signer_t signers[N_SIGNERS];
    const secp256k1_xonly_pubkey *pubkeys_ptr[N_SIGNERS];
    secp256k1_xonly_pubkey combined_pk;
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg!";
    unsigned char sig[64];

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    printf("Creating key pairs......");
    for (i = 0; i < N_SIGNERS; i++) {
        if (!create_keypair(ctx, &signer_secrets[i], &signers[i])) {
            printf("FAILED\n");
            return 1;
        }
        pubkeys_ptr[i] = &signers[i].pubkey;
    }
    printf("ok\n");
    printf("Combining public keys...");
    if (!secp256k1_musig_pubkey_combine(ctx, NULL, &combined_pk, NULL, pubkeys_ptr, N_SIGNERS)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Signing message.........");
    if (!sign(ctx, signer_secrets, signers, msg, sig)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    printf("Verifying signature.....");
    if (!secp256k1_schnorrsig_verify(ctx, sig, msg, &combined_pk)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");
    secp256k1_context_destroy(ctx);
    return 0;
}
