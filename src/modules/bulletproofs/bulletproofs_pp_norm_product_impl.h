/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_BULLETPROOFS_PP_NORM_PRODUCT_
#define _SECP256K1_MODULE_BULLETPROOFS_PP_NORM_PRODUCT_

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "hash.h"

#include "modules/bulletproofs/bulletproofs_util.h"

/* Computes the inner product of two vectors of scalars
 * with elements starting from offset a and offset b
 * skipping elements according to specified step.
 * Returns: Sum_i(a[offset_a + i*step] * b[offset_b + i*step]) */
static int secp256k1_scalar_inner_product(
    secp256k1_scalar* res,
    const secp256k1_scalar* a_vec,
    const size_t a_offset,
    const secp256k1_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len
) {
    size_t i;
    secp256k1_scalar_set_int(res, 0);
    for (i = 0; i < len; i++) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        secp256k1_scalar_add(res, res, &term);
    }
    return 1;
}

/* Computes the q-weighted inner product of two vectors of scalars
 * for elements starting from offset a and offset b respectively with the
 * given step.
 * Returns: Sum_i(a[offset_a + step*i] * b[offset_b2 + step*i]*q^(i+1)) */
static int secp256k1_weighted_scalar_inner_product(
    secp256k1_scalar* res,
    const secp256k1_scalar* a_vec,
    const size_t a_offset,
    const secp256k1_scalar* b_vec,
    const size_t b_offset,
    const size_t step,
    const size_t len,
    const secp256k1_scalar* q
) {
    secp256k1_scalar q_pow;
    size_t i;
    secp256k1_scalar_set_int(res, 0);
    q_pow = *q;
    for (i = 0; i < len; i++) {
        secp256k1_scalar term;
        secp256k1_scalar_mul(&term, &a_vec[a_offset + step*i], &b_vec[b_offset + step*i]);
        secp256k1_scalar_mul(&term, &term, &q_pow);
        secp256k1_scalar_mul(&q_pow, &q_pow, q);
        secp256k1_scalar_add(res, res, &term);
    }
    return 1;
}

/* Compute the powers of r as r, r^2, r^4 ... r^(2^(n-1)) */
static void secp256k1_bulletproofs_powers_of_r(secp256k1_scalar *powers, const secp256k1_scalar *r, size_t n) {
    size_t i;
    if (n == 0) {
        return;
    }
    powers[0] = *r;
    for (i = 1; i < n; i++) {
        secp256k1_scalar_sqr(&powers[i], &powers[i - 1]);
    }
}

typedef struct ec_mult_bp_commit_cb_data {
    const secp256k1_scalar *n;
    const secp256k1_ge *g;
    const secp256k1_scalar *l;
    size_t g_len;
} ec_mult_bp_commit_cb_data;

static int ec_mult_bp_commit_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ec_mult_bp_commit_cb_data *data = (ec_mult_bp_commit_cb_data*) cbdata;
    *pt = data->g[idx];
    if (idx < data->g_len) {
        *sc = data->n[idx];
    } else {
        *sc = data->l[idx - data->g_len];
    }
    return 1;
}

/* Create a commitment C = vG + [n_vec*G_vec]_q + l_vec*H_vec */
static int secp256k1_bulletproofs_commit(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    secp256k1_ge* commit,
    const secp256k1_bulletproofs_generators* g_vec,
    const secp256k1_scalar* n_vec,
    size_t n_vec_len,
    const secp256k1_scalar* l_vec,
    size_t l_vec_len,
    const secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_scalar* q
) {
    secp256k1_scalar v, l_c;
    /* First n_vec_len generators are Gs, rest are Hs*/
    CHECK(g_vec->n == (n_vec_len + l_vec_len));
    CHECK(l_vec_len == c_vec_len);

    /* It is possible to extend to support n_vec and c_vec to not be power of
    two. For the initial iterations of the code, we stick to powers of two for simplicity.*/
    CHECK(secp256k1_check_power_of_two(n_vec_len));
    CHECK(secp256k1_check_power_of_two(c_vec_len));

    /* Compute v = n_vec*n_vec*q + l_vec*c_vec */
    secp256k1_weighted_scalar_inner_product(&v, n_vec, 0 /*a offset */, n_vec, 0 /*b offset*/, 1 /*step*/, n_vec_len, q);
    secp256k1_scalar_inner_product(&l_c, l_vec, 0 /*a offset */, c_vec, 0 /*b offset*/, 1 /*step*/, l_vec_len);
    secp256k1_scalar_add(&v, &v, &l_c);

    {
        ec_mult_bp_commit_cb_data data;
        secp256k1_gej commitj;
        data.g = g_vec->gens;
        data.n = n_vec;
        data.l = l_vec;
        data.g_len = n_vec_len;

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &commitj, &v, ec_mult_bp_commit_cb, (void*) &data, n_vec_len + l_vec_len)) {
            return 0;
        }
        secp256k1_ge_set_gej_var(commit, &commitj);
    }
    return 1;
}

typedef struct ec_mult_x_cb_data {
    const secp256k1_scalar *n;
    const secp256k1_ge *g;
    const secp256k1_scalar *l;
    const secp256k1_scalar *r;
    const secp256k1_scalar *r_inv;
    size_t G_GENS_LEN; /* Figure out initialization syntax so that this can also be const */
    size_t n_len;
} ec_mult_x_cb_data;

static int ec_mult_x_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ec_mult_x_cb_data *data = (ec_mult_x_cb_data*) cbdata;
    if (idx < data->n_len) {
        if (idx % 2 == 0) {
            secp256k1_scalar_mul(sc, &data->n[idx + 1], data->r);
            *pt = data->g[idx];
        } else {
            secp256k1_scalar_mul(sc, &data->n[idx - 1], data->r_inv);
            *pt = data->g[idx];
        }
    } else {
        idx -= data->n_len;
        if (idx % 2 == 0) {
            *sc = data->l[idx + 1];
            *pt = data->g[data->G_GENS_LEN + idx];
        } else {
            *sc = data->l[idx - 1];
            *pt = data->g[data->G_GENS_LEN + idx];
        }
    }
    return 1;
}

typedef struct ec_mult_r_cb_data {
    const secp256k1_scalar *n1;
    const secp256k1_ge *g1;
    const secp256k1_scalar *l1;
    size_t G_GENS_LEN;
    size_t n_len;
} ec_mult_r_cb_data;

static int ec_mult_r_cb(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ec_mult_r_cb_data *data = (ec_mult_r_cb_data*) cbdata;
    if (idx < data->n_len) {
        *sc = data->n1[2*idx + 1];
        *pt = data->g1[2*idx + 1];
    } else {
        idx -= data->n_len;
        *sc = data->l1[2*idx + 1];
        *pt = data->g1[data->G_GENS_LEN + 2*idx + 1];
    }
    return 1;
}

/* Recursively compute the norm argument proof satisfying the relation
 * <n_vec, n_vec>_q + <c_vec, l_vec> = v for some commitment
 * C = v*G + <n_vec, G_vec> + <l_vec, H_vec>. <x, x>_q is the weighted inner
 * product of x with itself, where the weights are the first n powers of q.
 * <x, x>_q = q*x_1^2 + q^2*x_2^2 + q^3*x_3^2 + ... + q^n*x_n^2
 *
 * The norm argument is not zero knowledge and does not operate on any secret data.
 * Thus the following code uses variable time operations while computing the proof.
*/
int secp256k1_bulletproofs_pp_rangeproof_norm_product_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    unsigned char* proof,
    size_t *proof_len,
    unsigned char *transcript_hash32, /* Transcript hash of the parent protocol */
    const secp256k1_scalar* r_ch,
    const secp256k1_bulletproofs_generators* g_vec,
    const secp256k1_scalar* n_vec,
    size_t n_vec_len,
    const secp256k1_scalar* l_vec,
    size_t l_vec_len,
    const secp256k1_scalar* c_vec,
    size_t c_vec_len,
    const secp256k1_ge* commit
) {
    secp256k1_scalar q, r = *r_ch;
    secp256k1_sha256 sha256;
    unsigned char ser_commit[33];
    size_t start_idx = 0;
    ec_mult_x_cb_data x_cb_data;
    ec_mult_r_cb_data r_cb_data;
    size_t g_len = n_vec_len, h_len = l_vec_len;
    const size_t G_GENS_LEN = g_len;
    /* The initial pointers to the callback function remain the same. We mutate
     * the values and len in loop*/
    secp256k1_scalar *ns, *ls, *cs;
    secp256k1_ge *gs, comm = *commit;
    size_t scratch_checkpoint;
    size_t log_n = secp256k1_bulletproofs_pp_log2(g_len), log_m = secp256k1_bulletproofs_pp_log2(h_len);
    size_t n_rounds = log_n > log_m ? log_n : log_m;

    /* Check proof sizes.*/
    if (*proof_len < 65 * n_rounds + 64) {
        return 0;
    }

    if (g_vec->n != (n_vec_len + l_vec_len) || l_vec_len != c_vec_len) {
        return 0;
    }

    if (!secp256k1_check_power_of_two(n_vec_len) ||  !secp256k1_check_power_of_two(c_vec_len)) {
        return 0;
    }
    /* We can get away with allocating only half the size of arrays and unrolling the first iteration of the loop.
     This would increase the code complexity and can be done as an optimization in a future PR. */
    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    ns = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, g_len * sizeof(secp256k1_scalar));
    ls = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(secp256k1_scalar));
    cs = (secp256k1_scalar*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, h_len * sizeof(secp256k1_scalar));
    gs = (secp256k1_ge*)secp256k1_scratch_alloc(&ctx->error_callback, scratch, (g_len + h_len) * sizeof(secp256k1_ge));
    if (ns == NULL || ls == NULL || cs == NULL || gs == NULL) {
        secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    memcpy(ns, n_vec, g_len * sizeof(secp256k1_scalar));
    memcpy(ls, l_vec, h_len * sizeof(secp256k1_scalar));
    memcpy(cs, c_vec, h_len * sizeof(secp256k1_scalar));
    memcpy(gs, g_vec->gens, (g_len + h_len) * sizeof(secp256k1_ge));

    x_cb_data.n = ns;
    x_cb_data.g = gs;
    x_cb_data.l = ls;
    x_cb_data.G_GENS_LEN = G_GENS_LEN;

    r_cb_data.n1 = ns;
    r_cb_data.g1 = gs;
    r_cb_data.l1 = ls;
    r_cb_data.G_GENS_LEN = G_GENS_LEN;
    secp256k1_scalar_sqr(&q, &r);


    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, transcript_hash32, 32);
    secp256k1_fe_normalize_var(&comm.x);
    secp256k1_fe_normalize_var(&comm.y);
    ser_commit[0] = 0x02 | secp256k1_fe_is_odd(&comm.y);
    secp256k1_fe_get_b32(&ser_commit[1], &comm.x);
    secp256k1_sha256_write(&sha256, ser_commit, 33);
    secp256k1_sha256_finalize(&sha256, transcript_hash32);

    while (g_len > 1 || h_len > 1) {
        size_t i, num_points;
        secp256k1_scalar q_sq, r_inv, c0_l1, c1_l0, x_v, c1_l1, r_v;
        secp256k1_gej rj, xj;
        secp256k1_ge ge;
        int overflow;
        secp256k1_scalar e;

        secp256k1_scalar_inverse_var(&r_inv, &r);
        secp256k1_scalar_sqr(&q_sq, &q);

        /* Compute the X commitment X = WIP(r_inv*n0,n1)_q2 * g + r<n1,G> + <r_inv*x0, G1> */
        secp256k1_scalar_inner_product(&c0_l1, cs, 0, ls, 1, 2, h_len/2);
        secp256k1_scalar_inner_product(&c1_l0, cs, 1, ls, 0, 2, h_len/2);
        secp256k1_weighted_scalar_inner_product(&x_v, ns, 0, ns, 1, 2, g_len/2, &q_sq);
        secp256k1_scalar_mul(&x_v, &x_v, &r_inv);
        secp256k1_scalar_add(&x_v, &x_v, &x_v);
        secp256k1_scalar_add(&x_v, &x_v, &c0_l1);
        secp256k1_scalar_add(&x_v, &x_v, &c1_l0);

        x_cb_data.r = &r;
        x_cb_data.r_inv = &r_inv;
        x_cb_data.n_len = g_len >= 2 ? g_len : 0;
        num_points = x_cb_data.n_len + (h_len >= 2 ? h_len : 0);

        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &xj, &x_v, ec_mult_x_cb, (void*)&x_cb_data, num_points)) {
            return 0;
        }

        secp256k1_weighted_scalar_inner_product(&r_v, ns, 1, ns, 1, 2, g_len/2, &q_sq);
        secp256k1_scalar_inner_product(&c1_l1, cs, 1, ls, 1, 2, h_len/2);
        secp256k1_scalar_add(&r_v, &r_v, &c1_l1);

        r_cb_data.n_len = g_len/2;
        num_points = r_cb_data.n_len + h_len/2;
        if (!secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &rj, &r_v, ec_mult_r_cb, (void*)&r_cb_data, num_points)) {
            return 0;
        }

        secp256k1_ge_set_gej_var(&ge, &xj);
        secp256k1_fe_normalize_var(&ge.x);
        secp256k1_fe_normalize_var(&ge.y);
        proof[start_idx] = secp256k1_fe_is_odd(&ge.y) << 1;
        secp256k1_fe_get_b32(&proof[start_idx + 1], &ge.x);
        secp256k1_ge_set_gej_var(&ge, &rj);
        secp256k1_fe_normalize_var(&ge.x);
        secp256k1_fe_normalize_var(&ge.y);
        proof[start_idx] |= secp256k1_fe_is_odd(&ge.y);
        secp256k1_fe_get_b32(&proof[start_idx + 33], &ge.x);

        /* x additionally covers the next 65 bytes */
        secp256k1_sha256_initialize(&sha256);
        secp256k1_sha256_write(&sha256, transcript_hash32, 32);
        secp256k1_sha256_write(&sha256, &proof[start_idx], 65);
        secp256k1_sha256_finalize(&sha256, transcript_hash32);
        secp256k1_scalar_set_b32(&e, transcript_hash32, &overflow); /* Ignore overflow*/

        if (g_len > 1) {
            for (i = 0; i < g_len; i = i + 2) {
                secp256k1_scalar nl, nr;
                secp256k1_gej gl, gr;
                secp256k1_scalar_mul(&nl, &ns[i], &r_inv);
                secp256k1_scalar_mul(&nr, &ns[i + 1], &e);
                secp256k1_scalar_add(&ns[i/2], &nl, &nr);

                secp256k1_gej_set_ge(&gl, &gs[i]);
                secp256k1_ecmult(&gl, &gl, &r, NULL);
                secp256k1_gej_set_ge(&gr, &gs[i + 1]);
                secp256k1_ecmult(&gr, &gr, &e, NULL);
                secp256k1_gej_add_var(&gl, &gl, &gr, NULL);
                secp256k1_ge_set_gej_var(&gs[i/2], &gl);
            }
        }

        if (h_len > 1) {
            for (i = 0; i < h_len; i = i + 2) {
                secp256k1_scalar temp1;
                secp256k1_gej grj;
                secp256k1_scalar_mul(&temp1, &cs[i + 1], &e);
                secp256k1_scalar_add(&cs[i/2], &cs[i], &temp1);

                secp256k1_scalar_mul(&temp1, &ls[i + 1], &e);
                secp256k1_scalar_add(&ls[i/2], &ls[i], &temp1);

                secp256k1_gej_set_ge(&grj, &gs[G_GENS_LEN + i + 1]);
                secp256k1_ecmult(&grj, &grj, &e, NULL);
                secp256k1_gej_add_ge_var(&grj, &grj, &gs[G_GENS_LEN + i], NULL);
                secp256k1_ge_set_gej_var(&gs[G_GENS_LEN + i/2], &grj);
            }
        }
        g_len = g_len / 2;
        h_len = h_len / 2;
        r = q;
        q = q_sq;
        start_idx += 65;
    }

    secp256k1_scalar_get_b32(&proof[start_idx], &ns[0]);
    secp256k1_scalar_get_b32(&proof[start_idx + 32], &ls[0]);
    *proof_len = start_idx + 64;
    secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
    return 1;
}
#endif
