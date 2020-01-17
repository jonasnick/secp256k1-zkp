#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <secp256k1.h>
#include <secp256k1_bulletproofs.h>

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
    const unsigned char value[32] = { 0x28, 0x38, 0x7b, 0xf1, 0x14, 0x18, 0xef, 0x01, 0x85, 0xb7, 0xa7, 0xd7, 0x3f, 0xd2, 0x85, 0xcf, 0x5d, 0x10, 0x27, 0x5b, 0xdb, 0xb5, 0x63, 0x9f, 0x16, 0x02, 0x40, 0xa7, 0x30, 0x52, 0xaa, 0xa5 };
    unsigned char nonce[32] = "my kingdom for some randomness!!";
    secp256k1_pedersen_commitment commitment;
    /* This means 2 gates, 1 commitment (with Vi), 0 bits, 5 constraints */
    FILE *fcirc = fopen("./src/modules/bulletproofs/bin_circuits/purify.circ", "r");
    char *inv_17_19_circ;
    secp256k1_bulletproof_circuit *simple;
    secp256k1_generator blinding_gen = secp256k1_generator_const_h;
    secp256k1_generator value_gen = secp256k1_generator_const_g;
    {
        long fsize;
        if (fcirc == NULL) {
            printf("ERR read circuit\n");
            return 0;
        }
        fseek(fcirc, 0, SEEK_END);
        fsize = ftell(fcirc);
        fseek(fcirc, 0, SEEK_SET);  /* same as rewind(f); */
        inv_17_19_circ = malloc(fsize + 1);
        fread(inv_17_19_circ, 1, fsize, fcirc);
        fclose(fcirc);
        inv_17_19_circ[fsize] = 0;
    }

    /* So implied is that L0*R0 = O0 and L1*R1 = O1 */
    simple = secp256k1_bulletproof_circuit_parse(ctx, inv_17_19_circ);
    if (simple == NULL) {
        printf("ERR parse\n");
        return 0;
    }

    blinds[0] = blind;
    scratch = secp256k1_scratch_space_create(ctx, 1000000);
    gens = secp256k1_bulletproof_generators_create(ctx, &blinding_gen, 2*2048, 1);
    if (gens == NULL) {
        printf("ERR create\n");
        return 0;
    }

    /* Everything in assn is private, the values `v` must end up in the "commitments" */
    assn = secp256k1_bulletproof_circuit_assignment_decode(ctx, "./src/modules/bulletproofs/bin_circuits/purify.assn");
    if (assn == NULL) {
        printf("ERR decoding\n");
        return 0;
    }

    if (!secp256k1_bulletproof_circuit_evaluate(simple, assn, value)) {
      printf("ERR eval\n");
      return 0;
    }

    /* This should prove that pedersen commitment v*H + r*G includes a v that satisfies the constraints */
    if (!secp256k1_bulletproof_circuit_prove(ctx, scratch, gens, simple, proof, &plen, assn, blinds, 1, nonce, &value_gen, NULL, 0)) {
        printf("ERR proving\n");
        return 0;
    }
   
    printf("plen = %ld\n", plen);
    printf("verifying\n");
    
    printf("committing\n");
    if (!secp256k1_pedersen_commit_char(ctx, &commitment, blinds[0], value, &value_gen, &blinding_gen)) {
        printf("ERR commit\n");
        return 0;
    }

    if (!secp256k1_bulletproof_circuit_verify(ctx, scratch, gens, simple, proof, plen, &commitment, 1, &value_gen, NULL, 0)) {
        printf("ERR verifying\n");
        return 0;
    }

    printf("Success\n");

    secp256k1_context_destroy(ctx);
    secp256k1_scratch_space_destroy(scratch);

    return 1;
}
