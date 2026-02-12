// SPDX-License-Identifier: GPL-2.0
/*
 * FALCON PQClean API wrapper - Verification Only
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
 * Verify a signature. Internal function; it assumes that the signature
 * buffer has the proper length and that the signature header byte has
 * already been checked. It uses the nonce and the compressed signature
 * value (without the header byte) and the public key.
 */
static int
do_verify(
	const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
	const uint8_t *m, size_t mlen, const uint8_t *pk)
{
	union {
		uint8_t b[2 * 512];
		uint64_t dummy_u64;
		fpr dummy_fpr;
	} *tmp;
	uint16_t *h, *hm;
	int16_t *sig;
	inner_shake256_context sc;
	size_t v;
	int ret = -1;

	/* Allocate working buffers (too large for kernel stack) */
	tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
	h = kmalloc(512 * sizeof(uint16_t), GFP_KERNEL);
	hm = kmalloc(512 * sizeof(uint16_t), GFP_KERNEL);
	sig = kmalloc(512 * sizeof(int16_t), GFP_KERNEL);

	if (!tmp || !h || !hm || !sig)
		goto cleanup;

	/*
	 * Decode public key.
	 */
	if (pk[0] != 0x00 + 9) {
		goto cleanup;
	}
	if (PQCLEAN_FALCON512_CLEAN_modq_decode(h, 9,
						pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
			!= PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
		goto cleanup;
	}
	PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h, 9);

	/*
	 * Decode signature.
	 */
	if (sigbuflen == 0) {
		goto cleanup;
	}

	v = PQCLEAN_FALCON512_CLEAN_comp_decode(sig, 9, sigbuf, sigbuflen);
	if (v == 0) {
		goto cleanup;
	}
	if (v != sigbuflen) {
		if (sigbuflen == PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES - NONCELEN - 1) {
			while (v < sigbuflen) {
				if (sigbuf[v++] != 0) {
					goto cleanup;
				}
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
	PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(&sc, hm, 9, tmp->b);
	inner_shake256_ctx_release(&sc);

	/*
	 * Verify signature.
	 */
	if (!PQCLEAN_FALCON512_CLEAN_verify_raw(hm, sig, h, 9, tmp->b)) {
		goto cleanup;
	}

	/* Success */
	ret = 0;

cleanup:
	kfree(tmp);
	kfree(h);
	kfree(hm);
	kfree(sig);
	return ret;
}

/* see api.h */
int
PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
	const uint8_t *sig, size_t siglen,
	const uint8_t *m, size_t mlen, const uint8_t *pk)
{
	if (siglen < 1 + NONCELEN) {
		return -1;
	}
	if (sig[0] != 0x30 + 9) {
		return -1;
	}
	return do_verify(sig + 1,
			 sig + 1 + NONCELEN, siglen - 1 - NONCELEN, m, mlen, pk);
}

/* see api.h */
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

	/*
	 * Decode signature length.
	 */
	sigbuflen = ((size_t)sm[0] << 8) | (size_t)sm[1];
	if (sigbuflen > (smlen - 2 - NONCELEN)) {
		return -1;
	}
	sigbuflen --;

	/*
	 * Nonce is right after the two-byte length.
	 */
	sigbuf = sm + 2 + NONCELEN;

	/*
	 * Message starts at: nonce + signature + header byte.
	 * Length is computed by subtracting header (2 bytes) + nonce (40 bytes)
	 * + signature + header byte.
	 */
	pmlen = smlen - 2 - NONCELEN - sigbuflen - 1;

	/*
	 * Message is after nonce + signature + header byte.
	 */
	if (sigbuf[sigbuflen] != 0x20 + 9) {
		return -1;
	}

	/*
	 * Verify signature.
	 */
	if (do_verify(sm + 2, sigbuf, sigbuflen,
		      sigbuf + sigbuflen + 1, pmlen, pk) < 0) {
		return -1;
	}

	/*
	 * Return plaintext.
	 */
	memmove(m, sigbuf + sigbuflen + 1, pmlen);
	*mlen = pmlen;
	return 0;
}
