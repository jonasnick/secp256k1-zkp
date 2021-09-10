/**********************************************************************
 * Copyright (c) 2021 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MUSIG_SESSION_
#define _SECP256K1_MODULE_MUSIG_SESSION_

static void secp256k1_musig_session_load(int *fin_nonce_parity, unsigned char *r32, secp256k1_scalar *b, secp256k1_scalar *e, secp256k1_scalar *s, const secp256k1_musig_session *session);

#endif
