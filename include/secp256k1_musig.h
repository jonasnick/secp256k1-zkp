#ifndef SECP256K1_MUSIG_H
#define SECP256K1_MUSIG_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** This module implements a Schnorr-based multi-signature scheme called MuSig2
 * (https://eprint.iacr.org/2020/1261). It is compatible with bip-schnorr.
 * There's an example C source file in the module's directory
 * (src/modules/musig/example.c) that demonstrates how it can be used.
 *
 * The module also supports adaptor signatures as described in
 * https://github.com/ElementsProject/scriptless-scripts/pull/24
 *
 * The documentation in this include file is for reference and may not be sufficient
 * for users to begin using the library. A full description of API usage can be found
 * in src/modules/musig/musig.md
 */

/** Data structure containing auxiliary data generated in `pubkey_combine` and
 *  required for `session_*_init`.
 *  Fields:
 *        magic: Set during initialization in `pubkey_combine` to allow
 *               detecting an uninitialized object.
 *      pk_hash: The 32-byte hash of the original public keys
 *    second_pk: Serialized x-coordinate of the second public key in the list. Is 0
 *               if there is none.
 *    pk_parity: Whether the MuSig-aggregated point was negated when
 *               converting it to the combined xonly pubkey.
 *     is_tweaked: Whether the combined pubkey was tweaked
 *          tweak: If is_tweaked, array with the 32-byte tweak
 * internal_key_parity: If is_tweaked, the parity of the combined pubkey
 *                 before tweaking
 */
typedef struct {
    uint64_t magic;
    unsigned char pk_hash[32];
    unsigned char second_pk[32];
    int pk_parity;
    int is_tweaked;
    unsigned char tweak[32];
    int internal_key_parity;
} secp256k1_musig_pre_session;


/** Opaque data structures
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It can,
 *  however, be safely copied/moved. If you need to convert to a format suitable
 *  for storage, transmission, or comparison, use the corresponding
 *  serialization and parsing functions.
 */

/** Guaranteed to be 32 bytes in size. Serialized and parsed with
 *  `musig_partial_signature_serialize` and `musig_partial_signature_parse`. */
typedef struct {
    unsigned char data[32];
} secp256k1_musig_partial_signature;

/** Guaranteed to be 64 bytes in size. No serialization and parsing functions
 *  (yet). */
typedef struct {
    unsigned char data[64];
} secp256k1_musig_template;

/** Guaranteed to be 65 bytes in size. No serialization and parsing functions
 *  (yet). */
typedef struct {
    unsigned char data[65];
} secp256k1_musig_session_cache;

/** Guaranteed to be 64 bytes in size. This structure is MUST NOT be copied or
 *  read or written to it directly. A signer who is online throughout the whole
 *  process and can keep this structure in memory can use the provided API
 *  functions for a safe standard workflow. See
 *  https://blockstream.com/2019/02/18/musig-a-new-multisignature-standard/ for
 *  more details about the risks associated with serializing or deserializing
 *  this structure. There are no serialization and parsing functions (yet).
 */
typedef struct {
    unsigned char data[64];
} secp256k1_musig_secnonce;

/** Computes a combined public key and the hash of the given public keys.
 *
 *  Different orders of `pubkeys` result in different `combined_pk`s.
 *
 *  The pubkeys can be sorted before combining with `secp256k1_xonly_sort` which
 *  ensures the same resulting `combined_pk` for the same multiset of pubkeys.
 *  This is useful to do before pubkey_combine, such that the order of pubkeys
 *  does not affect the combined public key.
 *
 *  Returns: 1 if the public keys were successfully combined, 0 otherwise
 *  Args:        ctx: pointer to a context object initialized for verification
 *                    (cannot be NULL)
 *           scratch: scratch space used to compute the combined pubkey by
 *                    multiexponentiation. If NULL, an inefficient algorithm is used.
 *  Out: combined_pk: the MuSig-combined xonly public key (cannot be NULL)
 *       pre_session: if non-NULL, pointer to a musig_pre_session struct to be used in
 *                    `musig_process_nonces` or `musig_pubkey_tweak_add`.
 *   In:     pubkeys: input array of pointers to public keys to combine. The order
 *                    is important; a different order will result in a different
 *                    combined public key (cannot be NULL)
 *         n_pubkeys: length of pubkeys array. Must be greater than 0.
 */
SECP256K1_API int secp256k1_musig_pubkey_combine(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_xonly_pubkey *combined_pk,
    secp256k1_musig_pre_session *pre_session,
    const secp256k1_xonly_pubkey * const* pubkeys,
    size_t n_pubkeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

/** Tweak an x-only public key by adding the generator multiplied with tweak32
 *  to it. The resulting output_pubkey with the given internal_pubkey and tweak
 *  passes `secp256k1_xonly_pubkey_tweak_test`.
 *
 *  This function is only useful before initializing a signing session. If you
 *  are only computing a public key, but not intending to create a signature for
 *  it, you can just use `secp256k1_xonly_pubkey_tweak_add`. Can only be called
 *  once with a given pre_session.
 *
 *  Returns: 0 if the arguments are invalid or the resulting public key would be
 *           invalid (only when the tweak is the negation of the corresponding
 *           secret key). 1 otherwise.
 *  Args:          ctx: pointer to a context object initialized for verification
 *                      (cannot be NULL)
 *         pre_session: pointer to a `musig_pre_session` struct initialized in
 *                      `musig_pubkey_combine` (cannot be NULL)
 *  Out: output_pubkey: pointer to a public key to store the result. Will be set
 *                      to an invalid value if this function returns 0 (cannot
 *                      be NULL)
 *  In: internal_pubkey: pointer to the `combined_pk` from
 *                       `musig_pubkey_combine` to which the tweak is applied.
 *                       (cannot be NULL).
 *              tweak32: pointer to a 32-byte tweak. If the tweak is invalid
 *                       according to secp256k1_ec_seckey_verify, this function
 *                       returns 0. For uniformly random 32-byte arrays the
 *                       chance of being invalid is negligible (around 1 in
 *                       2^128) (cannot be NULL).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_pubkey_tweak_add(
    const secp256k1_context* ctx,
    secp256k1_musig_pre_session *pre_session,
    secp256k1_pubkey *output_pubkey,
    const secp256k1_xonly_pubkey *internal_pubkey,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Starts a signing session
 *
 *  This function derives a secret nonce that will be required for signing and
 *  creates a public nonce that is intended to be sent to other signers.
 *
 *  MuSig differs from regular Schnorr signing in that implementers _must_ take
 *  special care to not reuse a nonce. This can be ensured by following these rules:
 *
 *  1. Always provide a unique session_id32. It is a "number used once".
 *  2. If you already know the signing key, message or combined public key, they
 *     can be optionally povided to derive the nonce and increase
 *     misuse-resistance. The extra_input32 argument can be used to provide
 *     additional data that does not repeat in normal scenarios, such as the
 *     current time.
 *  3. If you do not provide a seckey, session_id32 _must_ be UNIFORMLY RANDOM.
 *     If you do provide a seckey, session_id32 can instead be a counter (that
 *     must never repeat!). However, it is recommended to always choose
 *     session_id32 uniformly at random.
 *  4. Avoid copying (or serializing) the secnonce. This reduces the possibility
 *     that it is used more than once for signing.
 *
 *  Remember that nonce reuse will immediately leak the secret key!
 *
 *  Returns: 0 if the arguments are invalid and 1 otherwise
 *  Args:         ctx: pointer to a context object, initialized for signing (cannot
 *                     be NULL)
 *  Out:     secnonce: pointer to a structure to store the secret nonce
 *         pubnonce66: a 66-byte array to store the public nonce
 *  In:  session_id32: a 32-byte session_id32 as explained above. Must be
 *                     uniformly random unless you really know what you are
 *                     doing.
 *             seckey: the 32-byte secret key that will be used for signing if
 *                     already known (can be NULL)
 *              msg32: the 32-byte message that will be signed if already known
 *                     (can be NULL)
 *        combined_pk: the combined xonly public key of all signers if already
 *                     known (can be NULL)
 *      extra_input32: an optional 32-byte array that is input to the nonce
 *                     derivation function (can be NULL)
 */
SECP256K1_API int secp256k1_musig_session_init(
    const secp256k1_context* ctx,
    secp256k1_musig_secnonce *secnonce,
    unsigned char *pubnonce66,
    const unsigned char *session_id32,
    const unsigned char *seckey,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *combined_pk,
    const unsigned char *extra_input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4);

/** Takes the public nonces of all signers and computes a session cache that is
 *  required for signing and verification of partial signatures and a signature
 *  template that is required for combining partial signatures.
 *
 *  Returns: 0 if the arguments are invalid or if all signers sent invalid
 *           pubnonces, 1 otherwise
 *  Args:         ctx: pointer to a context object, initialized for verification
 *                     (cannot be NULL)
 * Out: session_cache: pointer to a struct to store the session_cache, which is
 *                     used for partial_sign and partial_verify
 *       sig_template: pointer to a struct to store a sig template, which is
 *                     used for partial_sig_combine
 *       nonce_parity: optional pointer to an integer that indicates the parity
 *                     of the combined public nonce. Used for adaptor
 *                     signatures. (can be NULL)
 * In:      pubnonces: array of pointers to the 66-byte pubnonces sent by the
 *                     signers
 *        n_pubnonces: number of elements in the pubnonces array. Must be
 *                     greater than 0.
 *              msg32: the 32-byte message to sign
 *        combined_pk: pointer to combined public key of all signers
 *        pre_session: pointer to the pre_session that was output when
 *                     combined_pk was created
 *            adaptor: optional pointer to an adaptor if this signing session is
 *                     part of an adaptor signature protocol (can be NULL)
 */
SECP256K1_API int secp256k1_musig_process_nonces(
    const secp256k1_context* ctx,
    secp256k1_musig_session_cache *session_cache,
    secp256k1_musig_template *sig_template,
    int *nonce_parity,
    const unsigned char * const* pubnonces,
    size_t n_pubnonces,
    const unsigned char *msg32,
    const secp256k1_xonly_pubkey *combined_pk,
    const secp256k1_musig_pre_session *pre_session,
    const secp256k1_pubkey *adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9);

/** Serialize a MuSig partial signature or adaptor signature
 *
 *  Returns: 1 when the signature could be serialized, 0 otherwise
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out32: pointer to a 32-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 */
SECP256K1_API int secp256k1_musig_partial_signature_serialize(
    const secp256k1_context* ctx,
    unsigned char *out32,
    const secp256k1_musig_partial_signature* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse and verify a MuSig partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in32: pointer to the 32-byte signature to be parsed
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature verification with it is
 *  guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_musig_partial_signature_parse(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature* sig,
    const unsigned char *in32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Produces a partial signature
 *
 *  This function sets the given secnonce to 0 and will abort if given a
 *  secnonce that is 0. This is a best effort attempt to protect against nonce
 *  reuse. However, this is of course easily defeated if the secnonce has been
 *  copied (or serialized). Remember that nonce reuse will immediately leak the
 *  secret key!
 *
 *  Returns: 0 if the arguments are invalid or the provided secnonce has already
 *           been used for signing, 1 otherwise
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  partial_sig: pointer to struct to store the partial signature
 *  In/Out:  secnonce: pointer to the secnonce struct created in
 *                     musig_session_init
 *  In:       keypair: pointer to keypair to sign the message with
 *        pre_session: pointer to the pre_session that was output when the
 *                     combined public key for this session
 *      session_cache: pointer to the session_cache that was created with
 *                     musig_process_nonces
 */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    secp256k1_musig_secnonce *secnonce,
    const secp256k1_keypair *keypair,
    const secp256k1_musig_pre_session *pre_session,
    const secp256k1_musig_session_cache *session_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Checks that an individual partial signature verifies
 *
 *  This function is essential when using protocols with adaptor signatures.
 *  However, it is not essential for regular MuSig's, in the sense that if any
 *  partial signatures does not verify, the full signature will also not verify, so the
 *  problem will be caught. But this function allows determining the specific party
 *  who produced an invalid signature, so that signing can be restarted without them.
 *
 *  Returns: 0 if the arguments are invalid or the partial signature does not
 *           verify
 *  Args         ctx: pointer to a context object, initialized for verification
 *                    (cannot be NULL)
 *  In:  partial_sig: pointer to partial signature to verify
 *        pubnonce66: the 66-byte pubnonce array sent by the signer who produced
 *                    the signature
 *            pubkey: public key of the signer who produced the signature
 *       pre_session: pointer to the pre_session that was output when the
 *                    combined public key for this session
 *     session_cache: pointer to the session_cache that was created with
 *                    musig_process_nonces
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_partial_signature *partial_sig,
    const unsigned char *pubnonce66,
    const secp256k1_xonly_pubkey *pubkey,
    const secp256k1_musig_pre_session *pre_session,
    const secp256k1_musig_session_cache *session_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Combines partial signatures
 *
 *  Returns: 0 if the arguments are invalid or a partial_sig is out of range, 1
 *           otherwise (which does NOT mean the resulting signature verifies).
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:        sig64: complete Schnorr signature (cannot be NULL)
 *  In:  sig_template: pointer to the sig_template that was created with
 *                     musig_process_nonces
 *       partial_sigs: array of pointers to partial signatures to combine
 *             n_sigs: number of elements in the partial_sigs array
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_combine(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const secp256k1_musig_template *sig_template,
    const secp256k1_musig_partial_signature * const* partial_sigs,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Converts a partial signature to an adaptor signature by adding a given secret
 *  adaptor.
 *
 *  Returns: 1: signature and secret adaptor contained valid values
 *           0: otherwise
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  adaptor_sig: adaptor signature to produce (cannot be NULL)
 *  In:   partial_sig: partial signature to tweak with secret adaptor (cannot be NULL)
 *      sec_adaptor32: 32-byte secret adaptor to add to the partial signature (cannot
 *                     be NULL)
 *       nonce_parity: the `nonce_parity` output of `musig_session_process_nonces`
 */
SECP256K1_API int secp256k1_musig_partial_sig_adapt(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *adaptor_sig,
    const secp256k1_musig_partial_signature *partial_sig,
    const unsigned char *sec_adaptor32,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts a secret adaptor from a MuSig, given all parties' partial
 *  signatures. This function will not fail unless given grossly invalid data; if it
 *  is merely given signatures that do not verify, the returned value will be
 *  nonsense. It is therefore important that all data be verified at earlier steps of
 *  any protocol that uses this function.
 *
 *  Returns: 1: signatures contained valid data such that an adaptor could be extracted
 *           0: otherwise
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:sec_adaptor32: 32-byte secret adaptor (cannot be NULL)
 *  In:         sig64: complete 2-of-2 signature (cannot be NULL)
 *       partial_sigs: array of partial signatures (cannot be NULL)
 *     n_partial_sigs: number of elements in partial_sigs array
 *   nonce_parity: the `nonce_parity` output of `musig_session_process_nonces`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_extract_secret_adaptor(
    const secp256k1_context* ctx,
    unsigned char *sec_adaptor32,
    const unsigned char *sig64,
    const secp256k1_musig_partial_signature *partial_sigs,
    size_t n_partial_sigs,
    int nonce_parity
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif
