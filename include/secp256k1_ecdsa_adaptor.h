#ifndef SECP256K1_ECDSA_ADAPTOR_H
#define SECP256K1_ECDSA_ADAPTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements single signer ECDSA adaptor signatures following
 *  "One-Time Verifiably Encrypted Signatures A.K.A. Adaptor Signatures" by
 *  Lloyd Fournier
 *  (https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-November/002316.html
 *  and https://github.com/LLFourn/one-time-VES/blob/master/main.pdf).
*/

/** A pointer to a function to deterministically generate a nonce.
 *
 *  Same as secp256k1_nonce_function_hardened with the exception of using the
 *  compressed 33-byte encoding for the pubkey argument.
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:     nonce32:   pointer to a 32-byte array to be filled by the function
 *  In:        msg32:   the 32-byte message hash being verified
 *             key32:   pointer to a 32-byte secret key
 *              pk33:   the 33-byte serialized pubkey corresponding to key32
 *              algo:   pointer to an array describing the signature algorithm
 *           algolen:   the length of the algo array
 *              data:   arbitrary data pointer that is passed through
 *
 *  Except for test cases, this function should compute some cryptographic hash of
 *  the message, the key, the pubkey, the algorithm description, and data.
 */
typedef int (*secp256k1_nonce_function_hardened_ecdsa_adaptor)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *pk33,
    const unsigned char *algo,
    size_t algolen,
    void *data
);

/** A modified BIP-340 nonce generation function. If a data pointer is passed, it is
 *  assumed to be a pointer to 32 bytes of auxiliary random data as defined in BIP-340.
 *  The hash will be tagged with algo after removing all terminating null bytes.
 */
SECP256K1_API extern const secp256k1_nonce_function_hardened_ecdsa_adaptor secp256k1_nonce_function_ecdsa_adaptor;

/** Encrypted Signing
 *
 *  Creates an adaptor signature, which includes a proof to verify the adaptor
 *  signature.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:             ctx: a secp256k1 context object, initialized for signing
 *  Out:   adaptor_sig162: pointer to 162 byte to store the returned signature
 *  In:          seckey32: pointer to 32 byte secret key that will be used for
 *                         signing
 *                 enckey: pointer to the encryption public key
 *                  msg32: pointer to the 32-byte message hash to sign
 *                noncefp: pointer to a nonce generation function. If NULL,
 *                         secp256k1_nonce_function_ecdsa_adaptor is used
 *                  ndata: pointer to arbitrary data used by the nonce generation
 *                         function (can be NULL). If it is non-NULL and
 *                         secp256k1_nonce_function_ecdsa_adaptor is used, then
 *                         ndata must be a pointer to 32-byte auxiliary randomness
 *                         as per BIP-340.
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_encrypt(
    const secp256k1_context* ctx,
    unsigned char *adaptor_sig162,
    unsigned char *seckey32,
    const secp256k1_pubkey *enckey,
    const unsigned char *msg32,
    secp256k1_nonce_function_hardened_ecdsa_adaptor noncefp,
    void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Encryption Verification
 *
 *  Verifies that the adaptor decryption key can be extracted from the adaptor signature
 *  and the completed ECDSA signature.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:            ctx: a secp256k1 context object, initialized for verification
 *  In:   adaptor_sig162: pointer to 162-byte signature to verify
 *                pubkey: pointer to the public key corresponding to the secret key
 *                        used for signing
 *                 msg32: pointer to the 32-byte message hash being verified
 *                enckey: pointer to the adaptor encryption public key
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_verify(
    const secp256k1_context* ctx,
    const unsigned char *adaptor_sig162,
    const secp256k1_pubkey *pubkey,
    const unsigned char *msg32,
    const secp256k1_pubkey *enckey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Signature Decryption
 *
 *  Derives an ECDSA signature from an adaptor signature and an adaptor decryption key.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:              ctx: a secp256k1 context object
 *  Out:               sig: pointer to the ECDSA signature to create
 *  In:           deckey32: pointer to 32-byte decryption secret key for the adaptor
 *                          encryption public key
 *          adaptor_sig162: pointer to 162-byte adaptor sig
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_decrypt(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *deckey32,
    const unsigned char *adaptor_sig162
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Decryption Key Recovery
 *
 *  Extracts the adaptor decryption key from the complete signature and the adaptor
 *  signature.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:             ctx: a secp256k1 context object, initialized for signing
 *  Out:         deckey32: pointer to 32-byte adaptor decryption key for the adaptor
 *                         encryption public key
 *  In:               sig: pointer to ECDSA signature to recover the adaptor decryption
 *                         key from
 *         adaptor_sig162: pointer to adaptor signature to recover the adaptor
 *                         decryption key from
 *                 enckey: pointer to the adaptor encryption public key
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_recover(
    const secp256k1_context* ctx,
    unsigned char *deckey32,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *adaptor_sig162,
    const secp256k1_pubkey *enckey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_ADAPTOR_H */
