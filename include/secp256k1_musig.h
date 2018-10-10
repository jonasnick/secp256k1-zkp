#ifndef SECP256K1_MUSIG_H
#define SECP256K1_MUSIG_H

/** Opaque data structure containing MuSig parameters, such as the public keys.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions.
 *
 *  This structure is initialized with `secp256k1_musig_init` and must be destroyed with
 *  `secp256k1_musig_destroy`.
 *
 *         scratch: scratch space used to store `n` MuSig pubkeys (cannot be NULL)
 *               n: number of public keys involved in the multisignature
 *       musig_pks: `n` MuSig tweaked public keys from the signers
 *     combined_pk: combination of the signers public keys
 */
typedef struct {
    secp256k1_scratch_space *scratch;
    size_t n;
    unsigned char ell[32];
    secp256k1_pubkey *pks;
    secp256k1_pubkey combined_pk;
} secp256k1_musig_config;

/** Secret key tweaked for MuSig. Create with `secp256k1_musig_tweak_secret_key`.
 *
 * This data structure is not opaque. It is guaranteed to be a 32-byte secret key
 * that works anywhere that ordinary secret keys may be used. It is a separate
 * type to help prevent API users mistakenly using untweaked secret keys with
 * MuSig, which would result in mysteriously invalid signatures being produced.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_musig_secret_key;

/** Opaque data structure that holds a MuSig partial signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 33 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_musig_partial_signature_serialize` and
 *  `secp256k1_musig_partial_signature_parse` functions.
 */
typedef struct {
    unsigned char data[33];
} secp256k1_musig_partial_signature;

/* Opaque data structure containing auxiliary data needed to validate partial
 * signatures. As above, the only guarantees is that this data will be 64 bytes
 * in size and may be memcpy/memcmp'd. There are no functions to serialize or
 * parse this data structure because it should never be transmitted or stored.
 *
 * TODO it needs to be serialized for memoryless hardware doesn't it
 */
typedef struct {
    unsigned char data[64];
} secp256k1_musig_validation_aux;

/** Data structure containing data on other signers to be used during signing
 *
 * This structure is initialized with `secp256k1_musig_signer_data_initialize`.
 * If the signer is present, its nonce commitment is stored and before signing
 * completed with that signer's actual public nonce. The structure is used only
 * for a single signing attempt.
 *
 *   present: flag indicating whether the signer provided its nonce
 *     index: index of the signer in the MuSig. Must be consistent with the order of the pubkeys in
 *            secp256k1_musig_init
 *    pubkey: public key that the signer will use for partial signing
 *    pubnon: public nonce, must be a valid curvepoint if the signer is `present`
 * noncommit: pre-commitment to the nonce, used when adhering to the MuSig protocol
 */
typedef struct {
    int present;
    size_t index;
    secp256k1_pubkey pubkey;
    secp256k1_pubkey pubnon;
    unsigned char noncommit[32];
} secp256k1_musig_signer_data;

/** Serialize a MuSig partial signature or adaptor signature
 *
 *  Returns: 1
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out33: pointer to a 33-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 */
SECP256K1_API int secp256k1_musig_partial_signature_serialize(
    const secp256k1_context* ctx,
    unsigned char *out33,
    const secp256k1_musig_partial_signature* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse and validate a MuSig partial signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in33: pointer to the 33-byte signature to be parsed
 *
 * After the call, sig will always be initialized. If parsing failed or the
 * encoded numbers are out of range, signature validation with it is
 * guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_musig_partial_signature_parse(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature* sig,
    const unsigned char *in33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Creates a MuSig configuration from an array of public keys.
 *
 * The musig_config object must be destroyed with `secp256k1_musig_config_destroy`.
 *
 * Returns 1 on success, 0 on failure.
 *
 *  Args:     ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *        scratch: scratch space used to store `n` MuSig pubkeys (cannot be NULL)
 *  Out: musig_config: filled with the initialized MuSig config data
 *  In:           pks: input public keys (cannot be NULL)
 *                  n: number of public keys involved in the multisignature and number of elements
 *                     in `pks`
 */
SECP256K1_API int secp256k1_musig_init(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_config *musig_config,
    const secp256k1_pubkey *pks,
    const size_t n
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Destroy a secp256k1 MuSig configuration.
 *
 *  The pointer may not be used afterwards.
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *      musig_config: MuSig configuration to destroy (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_config_destroy(
    const secp256k1_context* ctx,
    secp256k1_musig_config *musig_config
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Get the MuSig pubkey from the MuSig configuration
 *
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  Out: combined_pk: combined public key encoding the MuSig signing policy (cannot be NULL)
 *  In: musig_config: MuSig configuration for `combined_pk` (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_pubkey(
    const secp256k1_context* ctx,
    secp256k1_pubkey *combined_pk,
    const secp256k1_musig_config *musig_config
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Generate a uniformly random nonce for a MuSig multisignature or threshold signature
 *
 *  Returns 1 always.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:  secnon: pointer to the returned 32-byte secret nonce (cannot be NULL)
 *        pubnon: returned public nonce (cannot be NULL)
 *     noncommit: returned 32-byte nonce commitment, if non-NULL
 *  In:   seckey: secret signing key (cannot be NULL)
 *         msg32: 32-byte message to be signed (cannot be NULL)
 *       rngseed: unique 32-byte seed. Does not need to be random but MUST BE UNIQUE (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_multisig_generate_nonce(
    const secp256k1_context* ctx,
    unsigned char *secnon,
    secp256k1_pubkey *pubnon,
    unsigned char *noncommit,
    const unsigned char *seckey,
    const unsigned char *msg32,
    const unsigned char *rngseed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Initializes a signer data structure. `noncommit` should be provided and set
 * to the signer's nonce commitment. After all nonce commitments have been
 * received, the signers start to send out nonces. `secp256k1_musig_set_nonce`
 * will mark the signer actually present, upon receipt of a nonce consistent
 * with the precommitment.
 *
 * Always returns 1.
 *  Args:        ctx: pointer to a context object (cannot be NULL)
 *  Out:        data: pointer to the signer data to initialize (cannot be NULL)
 *  In: musig_config: MuSig configuration (cannot be NULL)
 *             index: index of the signer in the MuSig. Must be consistent with the order of the
 *                    pubkeys in secp256k1_musig_init
 *         noncommit: signer's nonce commitment (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_signer_data_initialize(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *data,
    const secp256k1_musig_config *musig_config,
    size_t index,
    const unsigned char *noncommit
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Checks a signer's public nonce against a precommitment to said nonce, and update data structure if they match
 *
 *  Returns: 1: commitment was valid, data structure updated
 *           0: commitment was invalid, nothing happened
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In/Out: data: pointer to the signer data to update (cannot be NULL)
 *  In:   pubnon: signer's alleged public nonce (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_set_nonce(
    const secp256k1_context* ctx,
    secp256k1_musig_signer_data *data,
    const secp256k1_pubkey *pubnon
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Produces a partial signature
 *
 *  Returns: 1: partial signature constructed
 *           0: invalid secret key, invalid keyshards, not enough signers and/or keyshards, calling signer not present
 *  Args:    ctx: pointer to a context object initialized for verification (cannot be NULL)
 *       scratch: scratch space used to compute the total nonce by multiexponentiation
 *  Out:
 *   partial_sig: partial signature (cannot be NULL)
 *           aux: auxillary data needed to verify other partial signatures (cannot be NULL)
 *  In/Out:
 *        secnon: 32-byte secret half of signer's nonce (cannot be NULL). Will be set to 0 during
 *                signing if no adaptor signature is produced, i.e. sec_adaptor is NULL. Fresh
 *                nonces must be generated with secp256k1_musig_multisig_generate_nonce using a
 *                unique rngseed. secnon is a nonce and therefore only to be used ONCE, no more.
 *                One shall be the number of uses, and the number of uses shall be one. Once the
 *                nonce is used in musig_partial_sign it shall be never reused. Failure to do this
 *                will result in the secret key being leaked.
 *  In: musig_config: MuSig configuration (cannot be NULL)
 *            seckey: 32-byte secret signing key to use (cannot be NULL)
 *             msg32: 32-byte message to be signed (cannot be NULL)
 *              data: array of public nonces and/or keyshards of all signers including this signer (cannot be NULL).
 *                    The order of signers must be the same as in combine_pubkey.
 *          my_index: index of the caller in the array of signer data
 *       sec_adaptor: 32-byte secret value to be subtracted from the signature, if an adaptor
 *                    signature is to be produced. Should be set to NULL for a normal
 *                    partial signature.
 */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    secp256k1_musig_partial_signature *partial_sig,
    secp256k1_musig_validation_aux *aux,
    unsigned char *secnon,
    const secp256k1_musig_config *musig_config,
    const unsigned char *seckey,
    const unsigned char *msg32,
    const secp256k1_musig_signer_data *data,
    size_t my_index,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9);

/** Checks that an individual partial signature is valid
 *
 * It is not essential to use this function, in the sense that if any partial
 * signatures are invalid, the full signature will also be invalid, so the
 * problem will be caught. But this function allows determining the specific
 * party who produced an invalid signature, so that signing can be restarted
 * without them.
 *
 *  Returns: 1: partial signature was valid
 *           0: invalid signature or bad data
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:   partial_sig: signature to check (cannot be NULL)
 *               data: signer data for this signer (not the whole array) (cannot be NULL)
 *                aux: auxillary data from `partial_sign` (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_verify(
    const secp256k1_context* ctx,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_signer_data *data,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Extracts the public adaptor implied by an adaptor signature
 *
 *  Returns: 1: adaptor signature was correctly encoded and had nontrivial
 *              adaptor
 *           0: invalid adaptor signature or invalid adaptor
 *  Args:         ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:  pub_adaptor: public adaptor point (cannot be NULL)
 *  In:   partial_sig: adaptor signature to extract public adaptor from (cannot be NULL)
 *               data: signer data for this signer (not the whole array) (cannot be NULL)
 *                aux: auxillary partial-signature validation data (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_extract(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pub_adaptor,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_signer_data *data,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Converts an adaptor signature to a partial signature by adding a given
 *  secret adaptor
 *
 *  Returns: 1: signature and secret adaptor contained valid values
 *           0: otherwise
 *  Args:         ctx: pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:  partial_sig: partial signature to produce (cannot be NULL)
 *  In:   adaptor_sig: adaptor signature to tweak with secret adaptor (cannot be NULL)
 *        sec_adaptor: secret adaptor to add to the adaptor signature
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_adapt(
    const secp256k1_context* ctx,
    secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_partial_signature *adaptor_sig,
    const unsigned char *sec_adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Combines partial signatures
 *
 *  Returns: 1: all partial signatures had valid data. Does NOT mean the resulting signature is valid.
 *           0: some partial signature had s/r out of range
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:          sig: complete signature (cannot be NULL)
 *  In:  musig_config: MuSig configuration (cannot be NULL)
 *        partial_sig: array of partial signatures to combine (cannot be NULL)
 *                aux: auxillary data from `partial_sign` (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_musig_partial_sig_combine(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig *sig,
    const secp256k1_musig_config *musig_config,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_validation_aux *aux
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Extracts a secret from a complete signature and an earlier-received adaptor signature
 *
 *  Returns: 1: successfully extracted the secret
 *           0: signatures were invalid or didn't have same nonce
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out:  sec_adaptor: pointer to array to be filled with 32-byte extracted secret (cannot be NULL)
 *  In:  musig_config: MuSig configuration (cannot be NULL)
 *           full_sig: complete signature (cannot be NULL)
 *        partial_sig: partial non-adaptor signature (in a many-party scheme this should be the
 *                     sum of all partial signatures that are not the adaptor signature) (cannot be NULL)
 *        adaptor_sig: adaptor signature to extract secret from (cannot be NULL)
 */
SECP256K1_API int secp256k1_musig_adaptor_signature_extract_secret(
    const secp256k1_context* ctx,
    unsigned char *sec_adaptor,
    const secp256k1_musig_config *musig_config,
    const secp256k1_schnorrsig *full_sig,
    const secp256k1_musig_partial_signature *partial_sig,
    const secp256k1_musig_partial_signature *adaptor_sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

#endif
