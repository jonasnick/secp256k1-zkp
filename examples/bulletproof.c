#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>
#include "src/scalar.h"

void printn(unsigned char *s, size_t n) {
    size_t i;
    for(i=0; i< n; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
}

void print_pubkey(const secp256k1_context* ctx, secp256k1_pubkey *pk) {
    unsigned char pkser[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pkser, &len, pk, SECP256K1_EC_COMPRESSED);
    printn(pkser, 33);
}

int get_randomness(unsigned char* rand32) {
    FILE *frand = fopen("/dev/urandom", "r");
    if (frand == NULL || !fread(rand32, 32, 1, frand)) {
        return 0;
    }
    return 1;
}

/* Create a key pair and store it in seckey and pubkey */
int create_key(const secp256k1_context* ctx, unsigned char* seckey, secp256k1_pubkey* pubkey) {
    int ret;
    FILE *frand = fopen("/dev/urandom", "r");
    do {
        if (!get_randomness(seckey)) {
            return 0;
        }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));
     ret = secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
    assert(ret);
    fclose(frand);
    return 1;
}

int main(void) {
    secp256k1_context *ctx= secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_scratch_space *scratch;
    secp256k1_bulletproof_generators *gens;
    unsigned char proof[4096];
    size_t plen = 4096;
    /* TODO can only create pointer due to unknown size so we can only read assn from file... */
    secp256k1_bulletproof_circuit_assignment *assn;
    const unsigned char blind[32] = "   i am not a blinding factor   ";
    const unsigned char *blinds[1];
    unsigned char nonce[32] = "my kingdom for some randomness!!";
    secp256k1_pedersen_commitment commitment;
    /* This means 2 gates, 1 commitment (with Vi), 0 bits, 5 constraints */
    const char inv_17_19_circ[] = "2,1,0,5; L0 = 17; 2*L1 - L0 = 21; O0 = 1; O1 = 1; V0 - L0 = 100;";
    /* So implied is that L0*R0 = O0 and L1*R1 = O1 */
    secp256k1_bulletproof_circuit *simple = secp256k1_bulletproof_circuit_parse(ctx, inv_17_19_circ);

    blinds[0] = blind;

    scratch = secp256k1_scratch_space_create(ctx, 100000);

    if (simple == NULL) {
        printf("ERR parse\n");
        return 0;
    }
    gens = secp256k1_bulletproof_generators_create(ctx, &secp256k1_generator_const_h, 256, 1);
    if (gens == NULL) {
        printf("ERR create\n");
        return 0;
    }

    /* Everything in assn is private, the values `v` must end up in the "commitments" */
    assn = secp256k1_bulletproof_circuit_assignment_decode(ctx, "foo.assn");
    if (assn == NULL) {
        printf("ERR decoding\n");
        return 0;
    }

    /* This should prove that pedersen commitment v*H + r*G includes a v that satisfies the constraints */
    if (!secp256k1_bulletproof_circuit_prove(ctx, scratch, gens, simple, proof, &plen, assn, blinds, 1, nonce, &secp256k1_generator_const_h, NULL, 0)) {
        printf("ERR proving\n");
        return 0;
    }

    if (!secp256k1_pedersen_commit(ctx, &commitment, blinds[0], 117, &secp256k1_generator_const_h, &secp256k1_generator_const_h)) {
        printf("ERR commit\n");
        return 0;
    }

    if (!secp256k1_bulletproof_circuit_verify(ctx, scratch, gens, simple, proof, plen, &commitment, 1, &secp256k1_generator_const_h, NULL, 0)) {
        printf("ERR verifying\n");
        return 0;
    }

    printf("Success\n");

    secp256k1_context_destroy(ctx);
    secp256k1_scratch_space_destroy(scratch);

    return 1;
}
