/**********************************************************************
 * Copyright (c) 2020 The libsecp256k1 Developers                     *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECCOMMIT_H
#define SECP256K1_ECCOMMIT_H

/** Helper function to add a 32-byte value to a scalar */
static int secp256k1_ec_seckey_tweak_add_helper(secp256k1_scalar *sec, const unsigned char *tweak);
/** Helper function to add a 32-byte value, times G, to an EC point */
static int secp256k1_ec_pubkey_tweak_add_helper(const secp256k1_ecmult_context* ecmult_ctx, secp256k1_ge *p, const unsigned char *tweak);

/** Compute an ec commitment tweak as hash(pubkey, data). */
static void secp256k1_ec_commit_tweak(unsigned char *tweak32, secp256k1_ge* pubp, secp256k1_sha256* sha, const unsigned char *data, size_t data_size);
/** Compute an ec commitment as pubkey + hash(pubkey, data)*G. */
static int secp256k1_ec_commit(const secp256k1_ecmult_context* ecmult_ctx, secp256k1_ge* commitp, const secp256k1_ge* pubp, secp256k1_sha256* sha, const unsigned char *data, size_t data_size);
/** Compute a secret key commitment as seckey + hash(pubkey, data). */
static int secp256k1_ec_commit_seckey(const secp256k1_ecmult_gen_context* ecmult_gen_ctx, secp256k1_scalar* seckey, secp256k1_ge* pubp, secp256k1_sha256* sha, const unsigned char *data, size_t data_size);
/** Verify an ec commitment as pubkey + hash(pubkey, data)*G ?= commitment. */
static int secp256k1_ec_commit_verify(const secp256k1_ecmult_context* ecmult_ctx, const secp256k1_ge* commitp, const secp256k1_ge* pubp, secp256k1_sha256* sha, const unsigned char *data, size_t data_size);

#endif /* SECP256K1_ECCOMMIT_H */
