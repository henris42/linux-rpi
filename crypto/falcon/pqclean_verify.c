// SPDX-License-Identifier: GPL-2.0
/*
 * FALCON PQClean API wrapper - Verification Only
 *
 * Parameterized by logn to support both FALCON-512 (logn=9) and
 * FALCON-1024 (logn=10). All internal functions already take logn;
 * this wrapper allocates appropriate buffers and dispatches.
 *
 * Adapted from PQClean reference implementation
 * https://github.com/PQClean/PQClean
 *
 * Original Copyright (c) 2017-2019 Falcon Project
 */

/* Kernel headers instead of libc */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "api.h"
#include "inner.h"

#define NONCELEN   40

/*
 * Padded signature body sizes (excluding nonce and header byte).
 * Used to accept zero-padded signatures in the padded format.
 */
static size_t falcon_padded_body_size(unsigned logn)
{
	switch (logn) {
	case 9:  return FALCON512_PADDED_CRYPTO_BYTES - NONCELEN - 1;
	case 10: return FALCON1024_PADDED_CRYPTO_BYTES - NONCELEN - 1;
	default: return 0;
	}
}

/*
 * Public key byte count (excluding header byte) for a given logn.
 * FALCON public keys are modq-encoded polynomials of n = 2^logn elements,
 * each 14 bits, plus a 1-byte header.
 */
static size_t falcon_pubkey_data_len(unsigned logn)
{
	switch (logn) {
	case 9:  return FALCON512_CRYPTO_PUBLICKEYBYTES - 1;
	case 10: return FALCON1024_CRYPTO_PUBLICKEYBYTES - 1;
	default: return 0;
	}
}

/*
 * Verify a signature. Internal function parameterized by logn.
 * It assumes the signature header byte has been checked and stripped.
 * It uses the nonce and the compressed signature value (without header)
 * and the public key.
 */
static int
do_verify(
	const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
	const uint8_t *m, size_t mlen, const uint8_t *pk, unsigned logn)
{
	size_t n = (size_t)1 << logn;
	uint8_t *tmp;
	uint16_t *h, *hm;
	int16_t *sig;
	inner_shake256_context sc;
	size_t v, pk_data_len;
	int ret = -1;

	/* Allocate working buffers (n-dependent sizes) */
	tmp = kmalloc(2 * n, GFP_KERNEL);
	h = kmalloc(n * sizeof(uint16_t), GFP_KERNEL);
	hm = kmalloc(n * sizeof(uint16_t), GFP_KERNEL);
	sig = kmalloc(n * sizeof(int16_t), GFP_KERNEL);

	if (!tmp || !h || !hm || !sig)
		goto cleanup;

	/*
	 * Decode public key.
	 * Header byte is 0x00 + logn.
	 */
	if (pk[0] != (uint8_t)logn)
		goto cleanup;
	pk_data_len = falcon_pubkey_data_len(logn);
	if (pk_data_len == 0)
		goto cleanup;
	if (PQCLEAN_FALCON512_CLEAN_modq_decode(h, logn,
						pk + 1, pk_data_len)
			!= pk_data_len)
		goto cleanup;
	PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h, logn);

	/*
	 * Decode signature.
	 */
	if (sigbuflen == 0)
		goto cleanup;

	v = PQCLEAN_FALCON512_CLEAN_comp_decode(sig, logn, sigbuf, sigbuflen);
	if (v == 0)
		goto cleanup;
	if (v != sigbuflen) {
		size_t padded_body = falcon_padded_body_size(logn);

		if (padded_body > 0 && sigbuflen == padded_body) {
			while (v < sigbuflen) {
				if (sigbuf[v++] != 0)
					goto cleanup;
			}
		} else {
			goto cleanup;
		}
	}

	/*
	 * Hash nonce + message into a vector.
	 */
	inner_shake256_init(&sc);
	inner_shake256_inject(&sc, nonce, NONCELEN);
	inner_shake256_inject(&sc, m, mlen);
	inner_shake256_flip(&sc);

	PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, hm, logn, tmp);
	inner_shake256_ctx_release(&sc);

	/*
	 * Verify signature.
	 */
	if (!PQCLEAN_FALCON512_CLEAN_verify_raw(hm, sig, h, logn, tmp))
		goto cleanup;

	/* Success */
	ret = 0;

cleanup:
	kfree(tmp);
	kfree(h);
	kfree(hm);
	kfree(sig);
	return ret;
}

/*
 * Verify a detached FALCON signature, parameterized by logn.
 * This is the primary entry point for the kernel crypto API.
 *
 * Signature format: [header_byte][nonce (40 bytes)][compressed_signature]
 * Header byte: 0x30 + logn
 */
int
falcon_crypto_sign_verify(
	const uint8_t *sig, size_t siglen,
	const uint8_t *m, size_t mlen, const uint8_t *pk,
	unsigned logn)
{
	if (logn < 9 || logn > 10)
		return -1;
	if (siglen < 1 + NONCELEN)
		return -1;
	if (sig[0] != (uint8_t)(0x30 + logn))
		return -1;

	return do_verify(sig + 1,
			 sig + 1 + NONCELEN, siglen - 1 - NONCELEN,
			 m, mlen, pk, logn);
}

/* Legacy FALCON-512 wrapper */
int
PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
	const uint8_t *sig, size_t siglen,
	const uint8_t *m, size_t mlen, const uint8_t *pk)
{
	return falcon_crypto_sign_verify(sig, siglen, m, mlen, pk, 9);
}

/* Legacy FALCON-512 open wrapper */
int
PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
	uint8_t *m, size_t *mlen,
	const uint8_t *sm, size_t smlen, const uint8_t *pk)
{
	const uint8_t *sigbuf;
	size_t pmlen, sigbuflen;

	if (smlen < 3 + NONCELEN) {
		return -1;
	}

	sigbuflen = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sigbuflen > (smlen - 2 - NONCELEN)) {
		return -1;
	}
	sigbuflen --;

	sigbuf = sm + 2 + NONCELEN;

	pmlen = smlen - 2 - NONCELEN - sigbuflen - 1;

	if (sigbuf[sigbuflen] != 0x20 + 9) {
		return -1;
	}

	if (do_verify(sm + 2, sigbuf, sigbuflen,
		      sigbuf + sigbuflen + 1, pmlen, pk, 9) < 0) {
		return -1;
	}

	memmove(m, sigbuf + sigbuflen + 1, pmlen);
	*mlen = pmlen;
	return 0;
}
